"""Built-in signature rule table: packer/protector, installer and managed-runtime markers.

The rules are written in the restricted YARA-style subset defined by ``rule_match``; the
table is compiled and checked at import, so a typo fails the first test run instead of
silently matching nothing.

Scope discipline: every rule here names bytes that a known tool writes into a file.  A
match says "this marker is present".  It does not prove the file is packed, that the
tool produced it, or that anything malicious happens - and section names, banners and
magic values can be forged or can occur inside unrelated data.  This table is a triage
lead, complementary to the structural packing analysis in ``packer_analysis``.
"""
from __future__ import annotations

import rule_match

RULES_VERSION = 1

# Lower-case tags the shipped table may use.  Custom rule sources are free to use any
# lower-case tag; this vocabulary keeps the built-in table reviewable.
TAG_VOCABULARY = frozenset({'packer', 'protector', 'compressor', 'installer', 'runtime', 'toolchain',
                            'anti-analysis', 'crypto', 'malware-behavior'})

RULES_SOURCE = r'''
rule upx_stub : packer compressor {
  meta:
    description = "UPX marker or the UPX packer banner"
  strings:
    $marker = "UPX!"
    $banner = "This file is packed with the UPX executable packer" ascii wide nocase
  condition:
    $marker or $banner
}

rule themida_winlicense : packer protector {
  meta:
    description = "Themida/WinLicense section names or banner"
  strings:
    $themida = ".themida"
    $winlice = ".winlice"
    $banner = "WinLicense" ascii wide nocase
  condition:
    any of them
}

rule vmprotect : packer protector {
  meta:
    description = "VMProtect section names"
  strings:
    $vmp0 = ".vmp0"
    $vmp1 = ".vmp1"
    $vmp2 = ".vmp2"
    $vmp3 = ".vmp3"
  condition:
    any of them
}

rule enigma_protector : protector {
  meta:
    description = "Enigma Protector section names"
  strings:
    $enigma1 = ".enigma1"
    $enigma2 = ".enigma2"
  condition:
    any of them
}

rule aspack : packer compressor {
  meta:
    description = "ASPack section names"
  strings:
    $aspack = ".aspack"
    $adata = ".adata"
  condition:
    any of them
}

rule mpress : packer compressor {
  meta:
    description = "MPRESS section names"
  strings:
    $one = ".MPRESS1"
    $two = ".MPRESS2"
  condition:
    any of them
}

rule pecompact : packer compressor {
  meta:
    description = "PECompact section names"
  strings:
    $compact = "pec2to"
    $module = "pec2mo"
  condition:
    any of them
}

rule petite : packer compressor {
  meta:
    description = "Petite section name"
  strings:
    $petite = ".petite"
  condition:
    any of them
}

rule nspack : packer compressor {
  meta:
    description = "NsPack section names"
  strings:
    $plain0 = "nsp0"
    $plain1 = "nsp1"
    $plain2 = "nsp2"
    $dotted0 = ".nsp0"
    $dotted1 = ".nsp1"
    $dotted2 = ".nsp2"
  condition:
    any of them
}

rule rlpack : packer compressor {
  meta:
    description = "RLPack section name"
  strings:
    $rlpack = ".RLPack"
  condition:
    any of them
}

rule yoda_protector : packer protector {
  meta:
    description = "Yoda's Protector section name"
  strings:
    $yoda = ".y0da"
  condition:
    any of them
}

rule pyinstaller_bundle : packer runtime {
  meta:
    description = "PyInstaller bootloader or archive markers"
  strings:
    $meipass = "MEIPASS"
    $archive = "PYZ-00.pyz"
    $manifest = "pyi-windows-manifest"
  condition:
    any of them
}

rule nsis_installer : installer {
  meta:
    description = "NSIS installer banner"
  strings:
    // "NullsoftInst" and "Nullsoft.NSIS" also live in Windows' application-compatibility
    // database (kernel32.dll), so only the long banner is used as the signature.
    $banner = "Nullsoft Install System"
  condition:
    any of them
}

rule inno_setup_installer : installer {
  meta:
    description = "Inno Setup installer headers"
  strings:
    $data = "Inno Setup Setup Data"
    $loader = "InnoSetupLdr"
  condition:
    any of them
}

rule dotnet_managed : runtime {
  meta:
    description = ".NET CLR metadata root (BSJB signature and #Strings heap)"
  strings:
    // The CLR metadata root always carries the BSJB signature followed by stream
    // headers that include "#Strings".  The mscoree.dll import and the _CorExeMain /
    // _CorDllMain entry-point stubs are *not* used: native Windows DLLs reference
    // mscoree.dll as a COM activation shim, and mixed-mode C++/CLI binaries import
    // the stubs, so those strings alone flag native code.  mscorlib.dll, in fact,
    // carries no _CorDllMain string, so an entry-point condition would miss it.
    $root = "BSJB"
    $strings = "#Strings"
  condition:
    $root and $strings
}

rule autoit_compiled : runtime {
  meta:
    description = "AutoIt3 compiled-script signature"
  strings:
    $magic = "AU3!EA"
  condition:
    $magic
}
'''


def validate():
    """Compile the shipped table and check every rule carries reviewable metadata."""
    try:
        compiled = rule_match.compile_rules(RULES_SOURCE, origin='builtin', version=RULES_VERSION)
    except rule_match.RuleError as error:
        raise ValueError('feature_rules does not compile: %s' % error)
    problems = []
    for rule in compiled.rules:
        description = str(rule['meta'].get('description', '')).strip()
        if not description:
            problems.append('rule %r has no description' % rule['id'])
        if not rule['tags']:
            problems.append('rule %r has no tags' % rule['id'])
        unknown = sorted(set(rule['tags']) - TAG_VOCABULARY)
        if unknown:
            problems.append('rule %r uses tags outside the vocabulary: %s' % (rule['id'], ', '.join(unknown)))
        if not rule['strings']:
            problems.append('rule %r has no strings' % rule['id'])
    if problems:
        raise ValueError('feature_rules is inconsistent: ' + '; '.join(problems))


validate()
