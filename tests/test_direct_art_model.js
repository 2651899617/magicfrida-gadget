const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(process.argv[2], 'utf8');
const start = source.indexOf('class ArtMethodMangler {\n');
const end = source.indexOf('\nfunction xposedIsSupported () {', start);
assert(start >= 0 && end > start);
const code = source.slice(start, end) + '\nthis.ArtMethodMangler = ArtMethodMangler;';
let checks = 0;

function context(options = {}) {
  const original = { id: 'original' };
  const clone = { id: 'clone' };
  const quick = { equals(other) { return other === options.nterp; } };
  const originalFields = { jniCode: 'original-jni', accessFlags: options.flags || 0,
    quickCode: quick, interpreterCode: 'original-interpreter' };
  const fields = new Map([[original, { ...originalFields }]]);
  const methods = new Map();
  const events = [];
  let firstPatch = true;
  const api = { kAccCompileDontBother: 0x02000000, artNterpEntryPoint: options.nterp || null,
    artQuickToInterpreterBridge: 'interpreter-bridge',
    artClassLinker: { quickGenericJniTrampoline: 'jni-trampoline' },
    artInterpreterToCompiledCodeBridge: 'compiled-bridge' };
  const sandbox = {
    Process: { arch: options.arch || 'arm64' },
    getAndroidApiLevel() { return options.apiLevel || 29; },
    unwrapMethodId(method) { return method; },
    fetchArtMethod(method) { return { ...fields.get(method) }; },
    cloneArtMethod(method) { fields.set(clone, { ...fields.get(method) }); events.push('clone'); return clone; },
    patchArtMethod(method, patch) {
      Object.assign(fields.get(method), patch);
      events.push(method === original ? 'patch-original' : 'patch-clone');
      if (options.failPatch && method === original && firstPatch) {
        firstPatch = false;
        throw new Error('simulated write failure');
      }
    },
    ensureArtKnowsHowToHandleReplacementMethods() { events.push('gc-and-oat'); },
    isArtQuickEntrypoint() { return !options.compiled; },
    xposedIsSupported() { return true; },
    kAccCriticalNative: 0x00200000, kAccFastNative: 0x00080000, kAccNative: 0x0100,
    kAccFastInterpreterToInterpreterInvoke: 0x40000000, kAccSingleImplementation: 0x08000000,
    kAccNterpEntryPointFastPathFlag: 0x00100000, kAccSkipAccessChecks: 0x00080000,
    kAccXposedHookedMethod: 0x10000000,
    artController: { replacedMethods: {
      set(method, replacement) { methods.set(method, replacement); events.push('register'); },
      delete(method) { methods.delete(method); events.push('unregister'); }
    } }
  };
  vm.runInNewContext(code, sandbox, { timeout: 1000 });
  return { mangler: new sandbox.ArtMethodMangler(original), original, clone, fields,
    originalFields, methods, events, api };
}

const model = context();
model.mangler.replace('replacement-jni', true, [], null, model.api);
assert.equal(model.fields.get(model.original).jniCode, 'replacement-jni'); checks++;
assert.equal(model.fields.get(model.clone).jniCode, 'original-jni'); checks++;
assert.equal(model.mangler.resolveTarget(), model.clone); checks++;
assert.equal(model.methods.get(model.original), model.clone); checks++;
assert(model.events.indexOf('gc-and-oat') < model.events.indexOf('patch-original')); checks++;
assert.equal(model.fields.get(model.clone).quickCode, model.originalFields.quickCode); checks++;
assert.throws(() => model.mangler.replace('again', true, [], null, model.api), /already replaced/); checks++;
model.mangler.revert(null);
assert.deepEqual(model.fields.get(model.original), model.originalFields); checks++;
assert.equal(model.methods.size, 0); checks++;
assert.equal(model.mangler.replacementMethodId, null); checks++;
assert.throws(() => model.mangler.resolveTarget(), /no original-call clone/); checks++;
const afterRevert = model.events.length;
model.mangler.revert(null);
assert.equal(model.events.length, afterRevert); checks++;

const rollback = context({ failPatch: true });
assert.throws(() => rollback.mangler.replace('impl', true, [], null, rollback.api), /simulated write failure/); checks++;
assert.deepEqual(rollback.fields.get(rollback.original), rollback.originalFields); checks++;
assert.equal(rollback.methods.size, 0); checks++;
assert.equal(rollback.mangler.originalMethod, null); checks++;

for (const options of [{ arch: 'x64' }, { apiLevel: 22 }, { compiled: true }, { flags: 0x10000000 }]) {
  const rejected = context(options);
  assert.throws(() => rejected.mangler.replace('impl', true, [], null, rejected.api)); checks++;
  assert.deepEqual(rejected.fields.get(rejected.original), rejected.originalFields); checks++;
  assert.equal(rejected.events.length, 0); checks++;
}

const nterp = context({ nterp: 'nterp-entry', compiled: true });
nterp.mangler.replace('impl', true, [], null, nterp.api);
assert.equal(nterp.fields.get(nterp.clone).quickCode, 'interpreter-bridge'); checks++;
assert.equal(nterp.fields.get(nterp.original).quickCode, 'jni-trampoline'); checks++;
assert.equal(nterp.mangler.resolveTarget(), nterp.clone); checks++;
const factorySource = fs.readFileSync(process.argv[3], 'utf8');
const invokeStart = factorySource.indexOf('    value (receiver, args) {\n      const env = vm.getEnv();');
const invokeEnd = factorySource.indexOf('\n  },\n  toString:', invokeStart);
assert(invokeStart >= 0 && invokeEnd > invokeStart);
const envEvents = [];
const cloneId = { id: 'original-call-clone' };
const calls = [];
const env = {
  handle: 'env',
  pushLocalFrame(capacity) { envEvents.push(['push', capacity]); },
  throwIfExceptionPending() { envEvents.push(['exception-check']); },
  popLocalFrame() { envEvents.push(['pop']); }
};
const factorySandbox = { vm: { getEnv() { return env; } }, api: {}, isArtVm: true,
  INSTANCE_METHOD: 1, STRATEGY_DIRECT: 2, STRATEGY_VIRTUAL: 3, NULL: null,
  getCurrentThreadId() { return 10; } };
const invoke = vm.runInNewContext('({' + factorySource.slice(invokeStart, invokeEnd) + '}).value',
  factorySandbox, { timeout: 1000 });
const wrapper = {
  _p: ['method', {}, 1, 'original-id', { fromJni(value) { return value; } }, [],
    function () { calls.push(['virtual']); },
    function (...args) { calls.push(['direct', ...args]); return 42; }],
  _r: { _m: { requiresDirectCall: true, resolveTarget() { return cloneId; } }, _c: new Set() }
};
const receiver = { $t: 3, $getHandle() { return 'receiver'; }, $copyClassHandle() { return 'class'; } };
assert.equal(invoke.call(wrapper, receiver, []), 42); checks++;
assert.equal(calls[0][0], 'direct'); checks++;
assert.equal(calls[0][4], cloneId); checks++;
assert.equal(calls.length, 1); checks++;
assert.equal(envEvents[envEvents.length - 1][0], 'pop'); checks++;

const setterStart = factorySource.indexOf('    set (fn) {\n      const params = this._p;');
const setterEnd = factorySource.indexOf('\n  },\n  returnType:', setterStart);
assert(setterStart >= 0 && setterEnd > setterStart);
const patchedMethods = new Set();
const failedWrapper = { _p: ['method', { $f: { _patchedMethods: patchedMethods } }, 1,
  'original-id', {}, []], _r: undefined };
const setterSandbox = { vm: {}, api: {}, INSTANCE_METHOD: 1, CONSTRUCTOR_METHOD: 4,
  implement() { return {}; },
  makeMethodMangler() { return { replace() { throw new Error('unsupported-entrypoint'); } }; } };
const setImplementation = vm.runInNewContext('({' + factorySource.slice(setterStart, setterEnd) + '}).set',
  setterSandbox, { timeout: 1000 });
assert.throws(() => setImplementation.call(failedWrapper, () => {}), /unsupported-entrypoint/); checks++;
assert.equal(failedWrapper._r, undefined); checks++;
assert.equal(patchedMethods.size, 0); checks++;
console.log('PASS direct ART source model:', checks, 'checks; no Android runtime claim');
