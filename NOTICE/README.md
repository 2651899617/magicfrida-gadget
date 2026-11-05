# Source and license notices

The checked-in Frida source fixtures are unmodified excerpts from the exact commits in versions.json; per-file copyright/license comments remain intact. Each version's spec.json records the full source path and SHA-256. Patches modify those works without removing their existing license or wxWindows exception.

- frida-core.COPYING: wxWindows Library Licence, Version 3.1, preserved verbatim from core 4f05cb60ce97660189962bfcf7ffca15e182848e / 317363ce8064e3ede421ded3e53e1d3ffcfd782d (identical copies).
- tests/fixtures/<version>/subprojects/frida-core Gadget/build/Droidy/Fruity files: unmodified fixed upstream sources, additionally indexed in patches/gadget-files.json. The independently written Gadget naming and optional JSON sidecar patches preserve upstream notices, protocols and constructor-ordering symbols; no article author's branded binary, App-private configuration writer or LIEF script is redistributed.
- frida-gum.COPYING: preserved verbatim from gum 88e78178f786bf8cea2172ed6aeff335f30dd299 / c73c1bbf24ab6bab4e46e11faedd051579e1e942, including Mozilla/Closure Compiler/regenerator BSD notices (identical copies).
- GNU-Library-GPL-2.0.txt: the base GNU Library General Public License referenced by those COPYING files.
- tests/fixtures/<version>/releng/deps.toml and deps.py: unmodified dependency build sources from the exact releng commits in versions.json, with byte hashes in patches/dependencies.json and patches/releng/<version>/spec.json. This records source pins, not a license audit or redistribution of the listed SDK packages.
- tests/fixtures/glib/<version>: unmodified excerpts from the fixed GLib commits recorded in patches/glib/<version>/spec.json, retaining their original license/copyright headers. The complete LGPL-2.1-or-later text is included at LICENSES/LGPL-2.1-or-later.txt in each fixture tree. Unlike Frida's own wxWindows exception, that exception is not assumed for these GLib works. The thread-labels source patches do not constitute a rebuilt SDK distribution.
- module/include/zygisk.hpp: public Zygisk API 5; its complete John "topjohnwu" Wu copyright and permissive license are preserved inside the file, without edits.
- tests/fixtures/java-bridge/6.3.9 and tests/fixtures/java-bridge/7.0.13: unmodified official npm source package files, pinned by the tarball SHA-512/SHA-1/SHA-256 and per-file SHA-256 in their respective patches/java-bridge/<version>/spec.json. Both packages declare `LGPL-2.0 WITH WxWindows-exception-3.1`; their existing per-file copyright headers are preserved. The standalone direct-art-gc patches are independently written and do not include xiaojia fork code. See the included GNU-Library-GPL-2.0.txt and frida-core.COPYING exception terms. Source preparation is not a compiled or runtime-tested bridge distribution.

The wxWindows exception covers binary object code under the stated terms; it is not a blanket permission to relicense all upstream source. No proprietary xiaojia/rusda Gadget, APK, loader or private implementation is distributed here.

Builds clone the complete fixed upstream source and dependency gitlinks. Their original notices remain available in those repositories; this directory is not a claim that every transitive SDK/npm/Go dependency has been exhaustively audited. Preserve upstream dependencies' applicable license notices when redistributing beyond the research build artifacts.

Fixed official source license links:

- https://raw.githubusercontent.com/frida/frida-core/4f05cb60ce97660189962bfcf7ffca15e182848e/COPYING
- https://raw.githubusercontent.com/frida/frida-core/317363ce8064e3ede421ded3e53e1d3ffcfd782d/COPYING
- https://raw.githubusercontent.com/frida/frida-gum/88e78178f786bf8cea2172ed6aeff335f30dd299/COPYING
- https://raw.githubusercontent.com/frida/frida-gum/c73c1bbf24ab6bab4e46e11faedd051579e1e942/COPYING
