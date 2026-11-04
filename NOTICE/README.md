# Source and license notices

The checked-in Frida source fixtures are unmodified excerpts from the exact commits in versions.json; per-file copyright/license comments remain intact. Each version's spec.json records the full source path and SHA-256. Patches modify those works without removing their existing license or wxWindows exception.

- frida-core.COPYING: wxWindows Library Licence, Version 3.1, preserved verbatim from core 4f05cb60ce97660189962bfcf7ffca15e182848e / 317363ce8064e3ede421ded3e53e1d3ffcfd782d (identical copies).
- frida-gum.COPYING: preserved verbatim from gum 88e78178f786bf8cea2172ed6aeff335f30dd299 / c73c1bbf24ab6bab4e46e11faedd051579e1e942, including Mozilla/Closure Compiler/regenerator BSD notices (identical copies).
- GNU-Library-GPL-2.0.txt: the base GNU Library General Public License referenced by those COPYING files.
- module/include/zygisk.hpp: public Zygisk API 5; its complete John "topjohnwu" Wu copyright and permissive license are preserved inside the file, without edits.

The wxWindows exception covers binary object code under the stated terms; it is not a blanket permission to relicense all upstream source. No proprietary xiaojia/rusda Gadget, APK, loader or private implementation is distributed here.

Builds clone the complete fixed upstream source and dependency gitlinks. Their original notices remain available in those repositories; this directory is not a claim that every transitive SDK/npm/Go dependency has been exhaustively audited. Preserve upstream dependencies' applicable license notices when redistributing beyond the research build artifacts.

Fixed official source license links:

- https://raw.githubusercontent.com/frida/frida-core/4f05cb60ce97660189962bfcf7ffca15e182848e/COPYING
- https://raw.githubusercontent.com/frida/frida-core/317363ce8064e3ede421ded3e53e1d3ffcfd782d/COPYING
- https://raw.githubusercontent.com/frida/frida-gum/88e78178f786bf8cea2172ed6aeff335f30dd299/COPYING
- https://raw.githubusercontent.com/frida/frida-gum/c73c1bbf24ab6bab4e46e11faedd051579e1e942/COPYING
