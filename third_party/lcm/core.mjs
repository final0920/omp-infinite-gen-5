// Pinned lossless-claude/lcm storage core. See PROVENANCE.json and LICENSE.
import { createRequire as __ig5CreateRequire } from "node:module"; const require = __ig5CreateRequire(import.meta.url);
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// scratch/lcm-build/node_modules/safe-regex/lib/analyzer.js
var require_analyzer = __commonJS({
  "scratch/lcm-build/node_modules/safe-regex/lib/analyzer.js"(exports, module) {
    var AnalyzerOptions = class {
      constructor(heuristic_replimit) {
        this.heuristic_replimit = heuristic_replimit;
      }
    };
    var Analyzer = class {
      constructor(analyzerOptions) {
        this.options = analyzerOptions;
      }
      // Subclasser must implement
      // Return boolean
      isVulnerable(regExp) {
        return false;
      }
      // Subclass must implement
      // Returns an AttackString or null
      genAttackString(regExp) {
        return null;
      }
    };
    module.exports = function(re, replimit) {
      let myRegExp = null;
      let ast = null;
      try {
        if (re instanceof RegExp) {
          myRegExp = re;
        } else if (typeof re === "string") {
          myRegExp = new RegExp(re);
        } else {
          myRegExp = new RegExp(String(re));
        }
        ast = regexpTree.parse(myRegExp);
      } catch (err) {
        return false;
      }
      let currentStarHeight = 0;
      let maxObservedStarHeight = 0;
      let repetitionCount = 0;
      regexpTree.traverse(ast, {
        Repetition: {
          pre({ node }) {
            repetitionCount++;
            currentStarHeight++;
            if (maxObservedStarHeight < currentStarHeight) {
              maxObservedStarHeight = currentStarHeight;
            }
          },
          post({ node }) {
            currentStarHeight--;
          }
        }
      });
      return maxObservedStarHeight <= 1 && repetitionCount <= replimit;
    };
    module.exports = {
      "AnalyzerOptions": AnalyzerOptions,
      "Analyzer": Analyzer
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/transforms/compat-dotall-s-transform.js
var require_compat_dotall_s_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/transforms/compat-dotall-s-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      // Whether `u` flag present. In which case we transform to
      // \u{10FFFF} instead of \uFFFF.
      _hasUFlag: false,
      // Only run this plugin if we have `s` flag.
      shouldRun: function shouldRun(ast) {
        var shouldRun2 = ast.flags.includes("s");
        if (!shouldRun2) {
          return false;
        }
        ast.flags = ast.flags.replace("s", "");
        this._hasUFlag = ast.flags.includes("u");
        return true;
      },
      Char: function Char(path) {
        var node = path.node;
        if (node.kind !== "meta" || node.value !== ".") {
          return;
        }
        var toValue = "\\uFFFF";
        var toSymbol = "\uFFFF";
        if (this._hasUFlag) {
          toValue = "\\u{10FFFF}";
          toSymbol = "\u{10FFFF}";
        }
        path.replace({
          type: "CharacterClass",
          expressions: [{
            type: "ClassRange",
            from: {
              type: "Char",
              value: "\\0",
              kind: "decimal",
              symbol: "\0"
            },
            to: {
              type: "Char",
              value: toValue,
              kind: "unicode",
              symbol: toSymbol
            }
          }]
        });
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/transforms/compat-named-capturing-groups-transform.js
var require_compat_named_capturing_groups_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/transforms/compat-named-capturing-groups-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      // To track the names of the groups, and return them
      // in the transform result state.
      //
      // A map from name to number: {foo: 2, bar: 4}
      _groupNames: {},
      /**
       * Initialises the trasnform.
       */
      init: function init() {
        this._groupNames = {};
      },
      /**
       * Returns extra state, which eventually is returned to
       */
      getExtra: function getExtra() {
        return this._groupNames;
      },
      Group: function Group(path) {
        var node = path.node;
        if (!node.name) {
          return;
        }
        this._groupNames[node.name] = node.number;
        delete node.name;
        delete node.nameRaw;
      },
      Backreference: function Backreference(path) {
        var node = path.node;
        if (node.kind !== "name") {
          return;
        }
        node.kind = "number";
        node.reference = node.number;
        delete node.referenceRaw;
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/transforms/compat-x-flag-transform.js
var require_compat_x_flag_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/transforms/compat-x-flag-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      RegExp: function RegExp2(_ref) {
        var node = _ref.node;
        if (node.flags.includes("x")) {
          node.flags = node.flags.replace("x", "");
        }
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/transforms/index.js
var require_transforms = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/transforms/index.js"(exports, module) {
    "use strict";
    module.exports = {
      // "dotAll" `s` flag
      dotAll: require_compat_dotall_s_transform(),
      // Named capturing groups.
      namedCapturingGroups: require_compat_named_capturing_groups_transform(),
      // `x` flag
      xFlag: require_compat_x_flag_transform()
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/generator/index.js
var require_generator = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/generator/index.js"(exports, module) {
    "use strict";
    function gen(node) {
      return node ? generator[node.type](node) : "";
    }
    var generator = {
      RegExp: function RegExp2(node) {
        return "/" + gen(node.body) + "/" + node.flags;
      },
      Alternative: function Alternative(node) {
        return (node.expressions || []).map(gen).join("");
      },
      Disjunction: function Disjunction(node) {
        return gen(node.left) + "|" + gen(node.right);
      },
      Group: function Group(node) {
        var expression = gen(node.expression);
        if (node.capturing) {
          if (node.name) {
            return "(?<" + (node.nameRaw || node.name) + ">" + expression + ")";
          }
          return "(" + expression + ")";
        }
        return "(?:" + expression + ")";
      },
      Backreference: function Backreference(node) {
        switch (node.kind) {
          case "number":
            return "\\" + node.reference;
          case "name":
            return "\\k<" + (node.referenceRaw || node.reference) + ">";
          default:
            throw new TypeError("Unknown Backreference kind: " + node.kind);
        }
      },
      Assertion: function Assertion(node) {
        switch (node.kind) {
          case "^":
          case "$":
          case "\\b":
          case "\\B":
            return node.kind;
          case "Lookahead": {
            var assertion = gen(node.assertion);
            if (node.negative) {
              return "(?!" + assertion + ")";
            }
            return "(?=" + assertion + ")";
          }
          case "Lookbehind": {
            var _assertion = gen(node.assertion);
            if (node.negative) {
              return "(?<!" + _assertion + ")";
            }
            return "(?<=" + _assertion + ")";
          }
          default:
            throw new TypeError("Unknown Assertion kind: " + node.kind);
        }
      },
      CharacterClass: function CharacterClass(node) {
        var expressions = node.expressions.map(gen).join("");
        if (node.negative) {
          return "[^" + expressions + "]";
        }
        return "[" + expressions + "]";
      },
      ClassRange: function ClassRange(node) {
        return gen(node.from) + "-" + gen(node.to);
      },
      Repetition: function Repetition(node) {
        return "" + gen(node.expression) + gen(node.quantifier);
      },
      Quantifier: function Quantifier(node) {
        var quantifier = void 0;
        var greedy = node.greedy ? "" : "?";
        switch (node.kind) {
          case "+":
          case "?":
          case "*":
            quantifier = node.kind;
            break;
          case "Range":
            if (node.from === node.to) {
              quantifier = "{" + node.from + "}";
            } else if (!node.to) {
              quantifier = "{" + node.from + ",}";
            } else {
              quantifier = "{" + node.from + "," + node.to + "}";
            }
            break;
          default:
            throw new TypeError("Unknown Quantifier kind: " + node.kind);
        }
        return "" + quantifier + greedy;
      },
      Char: function Char(node) {
        var value = node.value;
        switch (node.kind) {
          case "simple": {
            if (node.escaped) {
              return "\\" + value;
            }
            return value;
          }
          case "hex":
          case "unicode":
          case "oct":
          case "decimal":
          case "control":
          case "meta":
            return value;
          default:
            throw new TypeError("Unknown Char kind: " + node.kind);
        }
      },
      UnicodeProperty: function UnicodeProperty(node) {
        var escapeChar = node.negative ? "P" : "p";
        var namePart = void 0;
        if (!node.shorthand && !node.binary) {
          namePart = node.name + "=";
        } else {
          namePart = "";
        }
        return "\\" + escapeChar + "{" + namePart + node.value + "}";
      }
    };
    module.exports = {
      /**
       * Generates a regexp string from an AST.
       *
       * @param Object ast - an AST node
       */
      generate: gen
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/parser/unicode/parser-unicode-properties.js
var require_parser_unicode_properties = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/parser/unicode/parser-unicode-properties.js"(exports, module) {
    "use strict";
    var NON_BINARY_PROP_NAMES_TO_ALIASES = {
      General_Category: "gc",
      Script: "sc",
      Script_Extensions: "scx"
    };
    var NON_BINARY_ALIASES_TO_PROP_NAMES = inverseMap(NON_BINARY_PROP_NAMES_TO_ALIASES);
    var BINARY_PROP_NAMES_TO_ALIASES = {
      ASCII: "ASCII",
      ASCII_Hex_Digit: "AHex",
      Alphabetic: "Alpha",
      Any: "Any",
      Assigned: "Assigned",
      Bidi_Control: "Bidi_C",
      Bidi_Mirrored: "Bidi_M",
      Case_Ignorable: "CI",
      Cased: "Cased",
      Changes_When_Casefolded: "CWCF",
      Changes_When_Casemapped: "CWCM",
      Changes_When_Lowercased: "CWL",
      Changes_When_NFKC_Casefolded: "CWKCF",
      Changes_When_Titlecased: "CWT",
      Changes_When_Uppercased: "CWU",
      Dash: "Dash",
      Default_Ignorable_Code_Point: "DI",
      Deprecated: "Dep",
      Diacritic: "Dia",
      Emoji: "Emoji",
      Emoji_Component: "Emoji_Component",
      Emoji_Modifier: "Emoji_Modifier",
      Emoji_Modifier_Base: "Emoji_Modifier_Base",
      Emoji_Presentation: "Emoji_Presentation",
      Extended_Pictographic: "Extended_Pictographic",
      Extender: "Ext",
      Grapheme_Base: "Gr_Base",
      Grapheme_Extend: "Gr_Ext",
      Hex_Digit: "Hex",
      IDS_Binary_Operator: "IDSB",
      IDS_Trinary_Operator: "IDST",
      ID_Continue: "IDC",
      ID_Start: "IDS",
      Ideographic: "Ideo",
      Join_Control: "Join_C",
      Logical_Order_Exception: "LOE",
      Lowercase: "Lower",
      Math: "Math",
      Noncharacter_Code_Point: "NChar",
      Pattern_Syntax: "Pat_Syn",
      Pattern_White_Space: "Pat_WS",
      Quotation_Mark: "QMark",
      Radical: "Radical",
      Regional_Indicator: "RI",
      Sentence_Terminal: "STerm",
      Soft_Dotted: "SD",
      Terminal_Punctuation: "Term",
      Unified_Ideograph: "UIdeo",
      Uppercase: "Upper",
      Variation_Selector: "VS",
      White_Space: "space",
      XID_Continue: "XIDC",
      XID_Start: "XIDS"
    };
    var BINARY_ALIASES_TO_PROP_NAMES = inverseMap(BINARY_PROP_NAMES_TO_ALIASES);
    var GENERAL_CATEGORY_VALUE_TO_ALIASES = {
      Cased_Letter: "LC",
      Close_Punctuation: "Pe",
      Connector_Punctuation: "Pc",
      Control: ["Cc", "cntrl"],
      Currency_Symbol: "Sc",
      Dash_Punctuation: "Pd",
      Decimal_Number: ["Nd", "digit"],
      Enclosing_Mark: "Me",
      Final_Punctuation: "Pf",
      Format: "Cf",
      Initial_Punctuation: "Pi",
      Letter: "L",
      Letter_Number: "Nl",
      Line_Separator: "Zl",
      Lowercase_Letter: "Ll",
      Mark: ["M", "Combining_Mark"],
      Math_Symbol: "Sm",
      Modifier_Letter: "Lm",
      Modifier_Symbol: "Sk",
      Nonspacing_Mark: "Mn",
      Number: "N",
      Open_Punctuation: "Ps",
      Other: "C",
      Other_Letter: "Lo",
      Other_Number: "No",
      Other_Punctuation: "Po",
      Other_Symbol: "So",
      Paragraph_Separator: "Zp",
      Private_Use: "Co",
      Punctuation: ["P", "punct"],
      Separator: "Z",
      Space_Separator: "Zs",
      Spacing_Mark: "Mc",
      Surrogate: "Cs",
      Symbol: "S",
      Titlecase_Letter: "Lt",
      Unassigned: "Cn",
      Uppercase_Letter: "Lu"
    };
    var GENERAL_CATEGORY_VALUE_ALIASES_TO_VALUES = inverseMap(GENERAL_CATEGORY_VALUE_TO_ALIASES);
    var SCRIPT_VALUE_TO_ALIASES = {
      Adlam: "Adlm",
      Ahom: "Ahom",
      Anatolian_Hieroglyphs: "Hluw",
      Arabic: "Arab",
      Armenian: "Armn",
      Avestan: "Avst",
      Balinese: "Bali",
      Bamum: "Bamu",
      Bassa_Vah: "Bass",
      Batak: "Batk",
      Bengali: "Beng",
      Bhaiksuki: "Bhks",
      Bopomofo: "Bopo",
      Brahmi: "Brah",
      Braille: "Brai",
      Buginese: "Bugi",
      Buhid: "Buhd",
      Canadian_Aboriginal: "Cans",
      Carian: "Cari",
      Caucasian_Albanian: "Aghb",
      Chakma: "Cakm",
      Cham: "Cham",
      Cherokee: "Cher",
      Common: "Zyyy",
      Coptic: ["Copt", "Qaac"],
      Cuneiform: "Xsux",
      Cypriot: "Cprt",
      Cyrillic: "Cyrl",
      Deseret: "Dsrt",
      Devanagari: "Deva",
      Dogra: "Dogr",
      Duployan: "Dupl",
      Egyptian_Hieroglyphs: "Egyp",
      Elbasan: "Elba",
      Ethiopic: "Ethi",
      Georgian: "Geor",
      Glagolitic: "Glag",
      Gothic: "Goth",
      Grantha: "Gran",
      Greek: "Grek",
      Gujarati: "Gujr",
      Gunjala_Gondi: "Gong",
      Gurmukhi: "Guru",
      Han: "Hani",
      Hangul: "Hang",
      Hanifi_Rohingya: "Rohg",
      Hanunoo: "Hano",
      Hatran: "Hatr",
      Hebrew: "Hebr",
      Hiragana: "Hira",
      Imperial_Aramaic: "Armi",
      Inherited: ["Zinh", "Qaai"],
      Inscriptional_Pahlavi: "Phli",
      Inscriptional_Parthian: "Prti",
      Javanese: "Java",
      Kaithi: "Kthi",
      Kannada: "Knda",
      Katakana: "Kana",
      Kayah_Li: "Kali",
      Kharoshthi: "Khar",
      Khmer: "Khmr",
      Khojki: "Khoj",
      Khudawadi: "Sind",
      Lao: "Laoo",
      Latin: "Latn",
      Lepcha: "Lepc",
      Limbu: "Limb",
      Linear_A: "Lina",
      Linear_B: "Linb",
      Lisu: "Lisu",
      Lycian: "Lyci",
      Lydian: "Lydi",
      Mahajani: "Mahj",
      Makasar: "Maka",
      Malayalam: "Mlym",
      Mandaic: "Mand",
      Manichaean: "Mani",
      Marchen: "Marc",
      Medefaidrin: "Medf",
      Masaram_Gondi: "Gonm",
      Meetei_Mayek: "Mtei",
      Mende_Kikakui: "Mend",
      Meroitic_Cursive: "Merc",
      Meroitic_Hieroglyphs: "Mero",
      Miao: "Plrd",
      Modi: "Modi",
      Mongolian: "Mong",
      Mro: "Mroo",
      Multani: "Mult",
      Myanmar: "Mymr",
      Nabataean: "Nbat",
      New_Tai_Lue: "Talu",
      Newa: "Newa",
      Nko: "Nkoo",
      Nushu: "Nshu",
      Ogham: "Ogam",
      Ol_Chiki: "Olck",
      Old_Hungarian: "Hung",
      Old_Italic: "Ital",
      Old_North_Arabian: "Narb",
      Old_Permic: "Perm",
      Old_Persian: "Xpeo",
      Old_Sogdian: "Sogo",
      Old_South_Arabian: "Sarb",
      Old_Turkic: "Orkh",
      Oriya: "Orya",
      Osage: "Osge",
      Osmanya: "Osma",
      Pahawh_Hmong: "Hmng",
      Palmyrene: "Palm",
      Pau_Cin_Hau: "Pauc",
      Phags_Pa: "Phag",
      Phoenician: "Phnx",
      Psalter_Pahlavi: "Phlp",
      Rejang: "Rjng",
      Runic: "Runr",
      Samaritan: "Samr",
      Saurashtra: "Saur",
      Sharada: "Shrd",
      Shavian: "Shaw",
      Siddham: "Sidd",
      SignWriting: "Sgnw",
      Sinhala: "Sinh",
      Sogdian: "Sogd",
      Sora_Sompeng: "Sora",
      Soyombo: "Soyo",
      Sundanese: "Sund",
      Syloti_Nagri: "Sylo",
      Syriac: "Syrc",
      Tagalog: "Tglg",
      Tagbanwa: "Tagb",
      Tai_Le: "Tale",
      Tai_Tham: "Lana",
      Tai_Viet: "Tavt",
      Takri: "Takr",
      Tamil: "Taml",
      Tangut: "Tang",
      Telugu: "Telu",
      Thaana: "Thaa",
      Thai: "Thai",
      Tibetan: "Tibt",
      Tifinagh: "Tfng",
      Tirhuta: "Tirh",
      Ugaritic: "Ugar",
      Vai: "Vaii",
      Warang_Citi: "Wara",
      Yi: "Yiii",
      Zanabazar_Square: "Zanb"
    };
    var SCRIPT_VALUE_ALIASES_TO_VALUE = inverseMap(SCRIPT_VALUE_TO_ALIASES);
    function inverseMap(data) {
      var inverse = {};
      for (var name in data) {
        if (!data.hasOwnProperty(name)) {
          continue;
        }
        var value = data[name];
        if (Array.isArray(value)) {
          for (var i2 = 0; i2 < value.length; i2++) {
            inverse[value[i2]] = name;
          }
        } else {
          inverse[value] = name;
        }
      }
      return inverse;
    }
    function isValidName(name) {
      return NON_BINARY_PROP_NAMES_TO_ALIASES.hasOwnProperty(name) || NON_BINARY_ALIASES_TO_PROP_NAMES.hasOwnProperty(name) || BINARY_PROP_NAMES_TO_ALIASES.hasOwnProperty(name) || BINARY_ALIASES_TO_PROP_NAMES.hasOwnProperty(name);
    }
    function isValidValue(name, value) {
      if (isGeneralCategoryName(name)) {
        return isGeneralCategoryValue(value);
      }
      if (isScriptCategoryName(name)) {
        return isScriptCategoryValue(value);
      }
      return false;
    }
    function isAlias(name) {
      return NON_BINARY_ALIASES_TO_PROP_NAMES.hasOwnProperty(name) || BINARY_ALIASES_TO_PROP_NAMES.hasOwnProperty(name);
    }
    function isGeneralCategoryName(name) {
      return name === "General_Category" || name == "gc";
    }
    function isScriptCategoryName(name) {
      return name === "Script" || name === "Script_Extensions" || name === "sc" || name === "scx";
    }
    function isGeneralCategoryValue(value) {
      return GENERAL_CATEGORY_VALUE_TO_ALIASES.hasOwnProperty(value) || GENERAL_CATEGORY_VALUE_ALIASES_TO_VALUES.hasOwnProperty(value);
    }
    function isScriptCategoryValue(value) {
      return SCRIPT_VALUE_TO_ALIASES.hasOwnProperty(value) || SCRIPT_VALUE_ALIASES_TO_VALUE.hasOwnProperty(value);
    }
    function isBinaryPropertyName(name) {
      return BINARY_PROP_NAMES_TO_ALIASES.hasOwnProperty(name) || BINARY_ALIASES_TO_PROP_NAMES.hasOwnProperty(name);
    }
    function getCanonicalName(name) {
      if (NON_BINARY_ALIASES_TO_PROP_NAMES.hasOwnProperty(name)) {
        return NON_BINARY_ALIASES_TO_PROP_NAMES[name];
      }
      if (BINARY_ALIASES_TO_PROP_NAMES.hasOwnProperty(name)) {
        return BINARY_ALIASES_TO_PROP_NAMES[name];
      }
      return null;
    }
    function getCanonicalValue(value) {
      if (GENERAL_CATEGORY_VALUE_ALIASES_TO_VALUES.hasOwnProperty(value)) {
        return GENERAL_CATEGORY_VALUE_ALIASES_TO_VALUES[value];
      }
      if (SCRIPT_VALUE_ALIASES_TO_VALUE.hasOwnProperty(value)) {
        return SCRIPT_VALUE_ALIASES_TO_VALUE[value];
      }
      if (BINARY_ALIASES_TO_PROP_NAMES.hasOwnProperty(value)) {
        return BINARY_ALIASES_TO_PROP_NAMES[value];
      }
      return null;
    }
    module.exports = {
      isAlias,
      isValidName,
      isValidValue,
      isGeneralCategoryValue,
      isScriptCategoryValue,
      isBinaryPropertyName,
      getCanonicalName,
      getCanonicalValue,
      NON_BINARY_PROP_NAMES_TO_ALIASES,
      NON_BINARY_ALIASES_TO_PROP_NAMES,
      BINARY_PROP_NAMES_TO_ALIASES,
      BINARY_ALIASES_TO_PROP_NAMES,
      GENERAL_CATEGORY_VALUE_TO_ALIASES,
      GENERAL_CATEGORY_VALUE_ALIASES_TO_VALUES,
      SCRIPT_VALUE_TO_ALIASES,
      SCRIPT_VALUE_ALIASES_TO_VALUE
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/parser/generated/regexp-tree.js
var require_regexp_tree = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/parser/generated/regexp-tree.js"(exports, module) {
    "use strict";
    var _slicedToArray = /* @__PURE__ */ (function() {
      function sliceIterator(arr, i2) {
        var _arr = [];
        var _n = true;
        var _d = false;
        var _e = void 0;
        try {
          for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) {
            _arr.push(_s.value);
            if (i2 && _arr.length === i2) break;
          }
        } catch (err) {
          _d = true;
          _e = err;
        } finally {
          try {
            if (!_n && _i["return"]) _i["return"]();
          } finally {
            if (_d) throw _e;
          }
        }
        return _arr;
      }
      return function(arr, i2) {
        if (Array.isArray(arr)) {
          return arr;
        } else if (Symbol.iterator in Object(arr)) {
          return sliceIterator(arr, i2);
        } else {
          throw new TypeError("Invalid attempt to destructure non-iterable instance");
        }
      };
    })();
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    var yytext = void 0;
    var yyleng = void 0;
    var yy = {};
    var __ = void 0;
    var __loc = void 0;
    function yyloc(start, end) {
      if (!yy.options.captureLocations) {
        return null;
      }
      if (!start || !end) {
        return start || end;
      }
      return {
        startOffset: start.startOffset,
        endOffset: end.endOffset,
        startLine: start.startLine,
        endLine: end.endLine,
        startColumn: start.startColumn,
        endColumn: end.endColumn
      };
    }
    var EOF = "$";
    var productions = [[-1, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [0, 4, function(_1, _2, _3, _4, _1loc, _2loc, _3loc, _4loc) {
      __loc = yyloc(_1loc, _4loc);
      __ = Node({
        type: "RegExp",
        body: _2,
        flags: checkFlags(_4)
      }, loc(_1loc, _4loc || _3loc));
    }], [1, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [1, 0, function() {
      __loc = null;
      __ = "";
    }], [2, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [2, 2, function(_1, _2, _1loc, _2loc) {
      __loc = yyloc(_1loc, _2loc);
      __ = _1 + _2;
    }], [3, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [4, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [4, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      var _loc = null;
      if (_2loc) {
        _loc = loc(_1loc || _2loc, _3loc || _2loc);
      }
      ;
      __ = Node({
        type: "Disjunction",
        left: _1,
        right: _3
      }, _loc);
    }], [5, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      if (_1.length === 0) {
        __ = null;
        return;
      }
      if (_1.length === 1) {
        __ = Node(_1[0], __loc);
      } else {
        __ = Node({
          type: "Alternative",
          expressions: _1
        }, __loc);
      }
    }], [6, 0, function() {
      __loc = null;
      __ = [];
    }], [6, 2, function(_1, _2, _1loc, _2loc) {
      __loc = yyloc(_1loc, _2loc);
      __ = _1.concat(_2);
    }], [7, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Node(Object.assign({ type: "Assertion" }, _1), __loc);
    }], [7, 2, function(_1, _2, _1loc, _2loc) {
      __loc = yyloc(_1loc, _2loc);
      __ = _1;
      if (_2) {
        __ = Node({
          type: "Repetition",
          expression: _1,
          quantifier: _2
        }, __loc);
      }
    }], [8, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = { kind: "^" };
    }], [8, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = { kind: "$" };
    }], [8, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = { kind: "\\b" };
    }], [8, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = { kind: "\\B" };
    }], [8, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      __ = {
        kind: "Lookahead",
        assertion: _2
      };
    }], [8, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      __ = {
        kind: "Lookahead",
        negative: true,
        assertion: _2
      };
    }], [8, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      __ = {
        kind: "Lookbehind",
        assertion: _2
      };
    }], [8, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      __ = {
        kind: "Lookbehind",
        negative: true,
        assertion: _2
      };
    }], [9, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [9, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [9, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "simple", __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1.slice(1), "simple", __loc);
      __.escaped = true;
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "unicode", __loc);
      __.isSurrogatePair = true;
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "unicode", __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = UnicodeProperty(_1, __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "control", __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "hex", __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "oct", __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = GroupRefOrDecChar(_1, __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "meta", __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "meta", __loc);
    }], [10, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = NamedGroupRefOrChars(_1, _1loc);
    }], [11, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [11, 0], [12, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [12, 2, function(_1, _2, _1loc, _2loc) {
      __loc = yyloc(_1loc, _2loc);
      _1.greedy = false;
      __ = _1;
    }], [13, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Node({
        type: "Quantifier",
        kind: _1,
        greedy: true
      }, __loc);
    }], [13, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Node({
        type: "Quantifier",
        kind: _1,
        greedy: true
      }, __loc);
    }], [13, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Node({
        type: "Quantifier",
        kind: _1,
        greedy: true
      }, __loc);
    }], [13, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      var range = getRange(_1);
      __ = Node({
        type: "Quantifier",
        kind: "Range",
        from: range[0],
        to: range[0],
        greedy: true
      }, __loc);
    }], [13, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Node({
        type: "Quantifier",
        kind: "Range",
        from: getRange(_1)[0],
        greedy: true
      }, __loc);
    }], [13, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      var range = getRange(_1);
      __ = Node({
        type: "Quantifier",
        kind: "Range",
        from: range[0],
        to: range[1],
        greedy: true
      }, __loc);
    }], [14, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [14, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [15, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      var nameRaw = String(_1);
      var name = decodeUnicodeGroupName(nameRaw);
      if (!yy.options.allowGroupNameDuplicates && namedGroups.hasOwnProperty(name)) {
        throw new SyntaxError('Duplicate of the named group "' + name + '".');
      }
      namedGroups[name] = _1.groupNumber;
      __ = Node({
        type: "Group",
        capturing: true,
        name,
        nameRaw,
        number: _1.groupNumber,
        expression: _2
      }, __loc);
    }], [15, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      __ = Node({
        type: "Group",
        capturing: true,
        number: _1.groupNumber,
        expression: _2
      }, __loc);
    }], [16, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      __ = Node({
        type: "Group",
        capturing: false,
        expression: _2
      }, __loc);
    }], [17, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      __ = Node({
        type: "CharacterClass",
        negative: true,
        expressions: _2
      }, __loc);
    }], [17, 3, function(_1, _2, _3, _1loc, _2loc, _3loc) {
      __loc = yyloc(_1loc, _3loc);
      __ = Node({
        type: "CharacterClass",
        expressions: _2
      }, __loc);
    }], [18, 0, function() {
      __loc = null;
      __ = [];
    }], [18, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [19, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = [_1];
    }], [19, 2, function(_1, _2, _1loc, _2loc) {
      __loc = yyloc(_1loc, _2loc);
      __ = [_1].concat(_2);
    }], [19, 4, function(_1, _2, _3, _4, _1loc, _2loc, _3loc, _4loc) {
      __loc = yyloc(_1loc, _4loc);
      checkClassRange(_1, _3);
      __ = [Node({
        type: "ClassRange",
        from: _1,
        to: _3
      }, loc(_1loc, _3loc))];
      if (_4) {
        __ = __.concat(_4);
      }
    }], [20, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [20, 2, function(_1, _2, _1loc, _2loc) {
      __loc = yyloc(_1loc, _2loc);
      __ = [_1].concat(_2);
    }], [20, 4, function(_1, _2, _3, _4, _1loc, _2loc, _3loc, _4loc) {
      __loc = yyloc(_1loc, _4loc);
      checkClassRange(_1, _3);
      __ = [Node({
        type: "ClassRange",
        from: _1,
        to: _3
      }, loc(_1loc, _3loc))];
      if (_4) {
        __ = __.concat(_4);
      }
    }], [21, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "simple", __loc);
    }], [21, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [22, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = _1;
    }], [22, 1, function(_1, _1loc) {
      __loc = yyloc(_1loc, _1loc);
      __ = Char(_1, "meta", __loc);
    }]];
    var tokens = { "SLASH": "23", "CHAR": "24", "BAR": "25", "BOS": "26", "EOS": "27", "ESC_b": "28", "ESC_B": "29", "POS_LA_ASSERT": "30", "R_PAREN": "31", "NEG_LA_ASSERT": "32", "POS_LB_ASSERT": "33", "NEG_LB_ASSERT": "34", "ESC_CHAR": "35", "U_CODE_SURROGATE": "36", "U_CODE": "37", "U_PROP_VALUE_EXP": "38", "CTRL_CH": "39", "HEX_CODE": "40", "OCT_CODE": "41", "DEC_CODE": "42", "META_CHAR": "43", "ANY": "44", "NAMED_GROUP_REF": "45", "Q_MARK": "46", "STAR": "47", "PLUS": "48", "RANGE_EXACT": "49", "RANGE_OPEN": "50", "RANGE_CLOSED": "51", "NAMED_CAPTURE_GROUP": "52", "L_PAREN": "53", "NON_CAPTURE_GROUP": "54", "NEG_CLASS": "55", "R_BRACKET": "56", "L_BRACKET": "57", "DASH": "58", "$": "59" };
    var table = [{ "0": 1, "23": "s2" }, { "59": "acc" }, { "3": 3, "4": 4, "5": 5, "6": 6, "23": "r10", "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "23": "s7" }, { "23": "r6", "25": "s12" }, { "23": "r7", "25": "r7", "31": "r7" }, { "7": 14, "8": 15, "9": 16, "10": 25, "14": 27, "15": 42, "16": 43, "17": 26, "23": "r9", "24": "s28", "25": "r9", "26": "s17", "27": "s18", "28": "s19", "29": "s20", "30": "s21", "31": "r9", "32": "s22", "33": "s23", "34": "s24", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "52": "s44", "53": "s45", "54": "s46", "55": "s40", "57": "s41" }, { "1": 8, "2": 9, "24": "s10", "59": "r3" }, { "59": "r1" }, { "24": "s11", "59": "r2" }, { "24": "r4", "59": "r4" }, { "24": "r5", "59": "r5" }, { "5": 13, "6": 6, "23": "r10", "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "31": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "23": "r8", "25": "r8", "31": "r8" }, { "23": "r11", "24": "r11", "25": "r11", "26": "r11", "27": "r11", "28": "r11", "29": "r11", "30": "r11", "31": "r11", "32": "r11", "33": "r11", "34": "r11", "35": "r11", "36": "r11", "37": "r11", "38": "r11", "39": "r11", "40": "r11", "41": "r11", "42": "r11", "43": "r11", "44": "r11", "45": "r11", "52": "r11", "53": "r11", "54": "r11", "55": "r11", "57": "r11" }, { "23": "r12", "24": "r12", "25": "r12", "26": "r12", "27": "r12", "28": "r12", "29": "r12", "30": "r12", "31": "r12", "32": "r12", "33": "r12", "34": "r12", "35": "r12", "36": "r12", "37": "r12", "38": "r12", "39": "r12", "40": "r12", "41": "r12", "42": "r12", "43": "r12", "44": "r12", "45": "r12", "52": "r12", "53": "r12", "54": "r12", "55": "r12", "57": "r12" }, { "11": 47, "12": 48, "13": 49, "23": "r38", "24": "r38", "25": "r38", "26": "r38", "27": "r38", "28": "r38", "29": "r38", "30": "r38", "31": "r38", "32": "r38", "33": "r38", "34": "r38", "35": "r38", "36": "r38", "37": "r38", "38": "r38", "39": "r38", "40": "r38", "41": "r38", "42": "r38", "43": "r38", "44": "r38", "45": "r38", "46": "s52", "47": "s50", "48": "s51", "49": "s53", "50": "s54", "51": "s55", "52": "r38", "53": "r38", "54": "r38", "55": "r38", "57": "r38" }, { "23": "r14", "24": "r14", "25": "r14", "26": "r14", "27": "r14", "28": "r14", "29": "r14", "30": "r14", "31": "r14", "32": "r14", "33": "r14", "34": "r14", "35": "r14", "36": "r14", "37": "r14", "38": "r14", "39": "r14", "40": "r14", "41": "r14", "42": "r14", "43": "r14", "44": "r14", "45": "r14", "52": "r14", "53": "r14", "54": "r14", "55": "r14", "57": "r14" }, { "23": "r15", "24": "r15", "25": "r15", "26": "r15", "27": "r15", "28": "r15", "29": "r15", "30": "r15", "31": "r15", "32": "r15", "33": "r15", "34": "r15", "35": "r15", "36": "r15", "37": "r15", "38": "r15", "39": "r15", "40": "r15", "41": "r15", "42": "r15", "43": "r15", "44": "r15", "45": "r15", "52": "r15", "53": "r15", "54": "r15", "55": "r15", "57": "r15" }, { "23": "r16", "24": "r16", "25": "r16", "26": "r16", "27": "r16", "28": "r16", "29": "r16", "30": "r16", "31": "r16", "32": "r16", "33": "r16", "34": "r16", "35": "r16", "36": "r16", "37": "r16", "38": "r16", "39": "r16", "40": "r16", "41": "r16", "42": "r16", "43": "r16", "44": "r16", "45": "r16", "52": "r16", "53": "r16", "54": "r16", "55": "r16", "57": "r16" }, { "23": "r17", "24": "r17", "25": "r17", "26": "r17", "27": "r17", "28": "r17", "29": "r17", "30": "r17", "31": "r17", "32": "r17", "33": "r17", "34": "r17", "35": "r17", "36": "r17", "37": "r17", "38": "r17", "39": "r17", "40": "r17", "41": "r17", "42": "r17", "43": "r17", "44": "r17", "45": "r17", "52": "r17", "53": "r17", "54": "r17", "55": "r17", "57": "r17" }, { "4": 57, "5": 5, "6": 6, "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "31": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "4": 59, "5": 5, "6": 6, "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "31": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "4": 61, "5": 5, "6": 6, "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "31": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "4": 63, "5": 5, "6": 6, "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "31": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "23": "r22", "24": "r22", "25": "r22", "26": "r22", "27": "r22", "28": "r22", "29": "r22", "30": "r22", "31": "r22", "32": "r22", "33": "r22", "34": "r22", "35": "r22", "36": "r22", "37": "r22", "38": "r22", "39": "r22", "40": "r22", "41": "r22", "42": "r22", "43": "r22", "44": "r22", "45": "r22", "46": "r22", "47": "r22", "48": "r22", "49": "r22", "50": "r22", "51": "r22", "52": "r22", "53": "r22", "54": "r22", "55": "r22", "57": "r22" }, { "23": "r23", "24": "r23", "25": "r23", "26": "r23", "27": "r23", "28": "r23", "29": "r23", "30": "r23", "31": "r23", "32": "r23", "33": "r23", "34": "r23", "35": "r23", "36": "r23", "37": "r23", "38": "r23", "39": "r23", "40": "r23", "41": "r23", "42": "r23", "43": "r23", "44": "r23", "45": "r23", "46": "r23", "47": "r23", "48": "r23", "49": "r23", "50": "r23", "51": "r23", "52": "r23", "53": "r23", "54": "r23", "55": "r23", "57": "r23" }, { "23": "r24", "24": "r24", "25": "r24", "26": "r24", "27": "r24", "28": "r24", "29": "r24", "30": "r24", "31": "r24", "32": "r24", "33": "r24", "34": "r24", "35": "r24", "36": "r24", "37": "r24", "38": "r24", "39": "r24", "40": "r24", "41": "r24", "42": "r24", "43": "r24", "44": "r24", "45": "r24", "46": "r24", "47": "r24", "48": "r24", "49": "r24", "50": "r24", "51": "r24", "52": "r24", "53": "r24", "54": "r24", "55": "r24", "57": "r24" }, { "23": "r25", "24": "r25", "25": "r25", "26": "r25", "27": "r25", "28": "r25", "29": "r25", "30": "r25", "31": "r25", "32": "r25", "33": "r25", "34": "r25", "35": "r25", "36": "r25", "37": "r25", "38": "r25", "39": "r25", "40": "r25", "41": "r25", "42": "r25", "43": "r25", "44": "r25", "45": "r25", "46": "r25", "47": "r25", "48": "r25", "49": "r25", "50": "r25", "51": "r25", "52": "r25", "53": "r25", "54": "r25", "55": "r25", "56": "r25", "57": "r25", "58": "r25" }, { "23": "r26", "24": "r26", "25": "r26", "26": "r26", "27": "r26", "28": "r26", "29": "r26", "30": "r26", "31": "r26", "32": "r26", "33": "r26", "34": "r26", "35": "r26", "36": "r26", "37": "r26", "38": "r26", "39": "r26", "40": "r26", "41": "r26", "42": "r26", "43": "r26", "44": "r26", "45": "r26", "46": "r26", "47": "r26", "48": "r26", "49": "r26", "50": "r26", "51": "r26", "52": "r26", "53": "r26", "54": "r26", "55": "r26", "56": "r26", "57": "r26", "58": "r26" }, { "23": "r27", "24": "r27", "25": "r27", "26": "r27", "27": "r27", "28": "r27", "29": "r27", "30": "r27", "31": "r27", "32": "r27", "33": "r27", "34": "r27", "35": "r27", "36": "r27", "37": "r27", "38": "r27", "39": "r27", "40": "r27", "41": "r27", "42": "r27", "43": "r27", "44": "r27", "45": "r27", "46": "r27", "47": "r27", "48": "r27", "49": "r27", "50": "r27", "51": "r27", "52": "r27", "53": "r27", "54": "r27", "55": "r27", "56": "r27", "57": "r27", "58": "r27" }, { "23": "r28", "24": "r28", "25": "r28", "26": "r28", "27": "r28", "28": "r28", "29": "r28", "30": "r28", "31": "r28", "32": "r28", "33": "r28", "34": "r28", "35": "r28", "36": "r28", "37": "r28", "38": "r28", "39": "r28", "40": "r28", "41": "r28", "42": "r28", "43": "r28", "44": "r28", "45": "r28", "46": "r28", "47": "r28", "48": "r28", "49": "r28", "50": "r28", "51": "r28", "52": "r28", "53": "r28", "54": "r28", "55": "r28", "56": "r28", "57": "r28", "58": "r28" }, { "23": "r29", "24": "r29", "25": "r29", "26": "r29", "27": "r29", "28": "r29", "29": "r29", "30": "r29", "31": "r29", "32": "r29", "33": "r29", "34": "r29", "35": "r29", "36": "r29", "37": "r29", "38": "r29", "39": "r29", "40": "r29", "41": "r29", "42": "r29", "43": "r29", "44": "r29", "45": "r29", "46": "r29", "47": "r29", "48": "r29", "49": "r29", "50": "r29", "51": "r29", "52": "r29", "53": "r29", "54": "r29", "55": "r29", "56": "r29", "57": "r29", "58": "r29" }, { "23": "r30", "24": "r30", "25": "r30", "26": "r30", "27": "r30", "28": "r30", "29": "r30", "30": "r30", "31": "r30", "32": "r30", "33": "r30", "34": "r30", "35": "r30", "36": "r30", "37": "r30", "38": "r30", "39": "r30", "40": "r30", "41": "r30", "42": "r30", "43": "r30", "44": "r30", "45": "r30", "46": "r30", "47": "r30", "48": "r30", "49": "r30", "50": "r30", "51": "r30", "52": "r30", "53": "r30", "54": "r30", "55": "r30", "56": "r30", "57": "r30", "58": "r30" }, { "23": "r31", "24": "r31", "25": "r31", "26": "r31", "27": "r31", "28": "r31", "29": "r31", "30": "r31", "31": "r31", "32": "r31", "33": "r31", "34": "r31", "35": "r31", "36": "r31", "37": "r31", "38": "r31", "39": "r31", "40": "r31", "41": "r31", "42": "r31", "43": "r31", "44": "r31", "45": "r31", "46": "r31", "47": "r31", "48": "r31", "49": "r31", "50": "r31", "51": "r31", "52": "r31", "53": "r31", "54": "r31", "55": "r31", "56": "r31", "57": "r31", "58": "r31" }, { "23": "r32", "24": "r32", "25": "r32", "26": "r32", "27": "r32", "28": "r32", "29": "r32", "30": "r32", "31": "r32", "32": "r32", "33": "r32", "34": "r32", "35": "r32", "36": "r32", "37": "r32", "38": "r32", "39": "r32", "40": "r32", "41": "r32", "42": "r32", "43": "r32", "44": "r32", "45": "r32", "46": "r32", "47": "r32", "48": "r32", "49": "r32", "50": "r32", "51": "r32", "52": "r32", "53": "r32", "54": "r32", "55": "r32", "56": "r32", "57": "r32", "58": "r32" }, { "23": "r33", "24": "r33", "25": "r33", "26": "r33", "27": "r33", "28": "r33", "29": "r33", "30": "r33", "31": "r33", "32": "r33", "33": "r33", "34": "r33", "35": "r33", "36": "r33", "37": "r33", "38": "r33", "39": "r33", "40": "r33", "41": "r33", "42": "r33", "43": "r33", "44": "r33", "45": "r33", "46": "r33", "47": "r33", "48": "r33", "49": "r33", "50": "r33", "51": "r33", "52": "r33", "53": "r33", "54": "r33", "55": "r33", "56": "r33", "57": "r33", "58": "r33" }, { "23": "r34", "24": "r34", "25": "r34", "26": "r34", "27": "r34", "28": "r34", "29": "r34", "30": "r34", "31": "r34", "32": "r34", "33": "r34", "34": "r34", "35": "r34", "36": "r34", "37": "r34", "38": "r34", "39": "r34", "40": "r34", "41": "r34", "42": "r34", "43": "r34", "44": "r34", "45": "r34", "46": "r34", "47": "r34", "48": "r34", "49": "r34", "50": "r34", "51": "r34", "52": "r34", "53": "r34", "54": "r34", "55": "r34", "56": "r34", "57": "r34", "58": "r34" }, { "23": "r35", "24": "r35", "25": "r35", "26": "r35", "27": "r35", "28": "r35", "29": "r35", "30": "r35", "31": "r35", "32": "r35", "33": "r35", "34": "r35", "35": "r35", "36": "r35", "37": "r35", "38": "r35", "39": "r35", "40": "r35", "41": "r35", "42": "r35", "43": "r35", "44": "r35", "45": "r35", "46": "r35", "47": "r35", "48": "r35", "49": "r35", "50": "r35", "51": "r35", "52": "r35", "53": "r35", "54": "r35", "55": "r35", "56": "r35", "57": "r35", "58": "r35" }, { "23": "r36", "24": "r36", "25": "r36", "26": "r36", "27": "r36", "28": "r36", "29": "r36", "30": "r36", "31": "r36", "32": "r36", "33": "r36", "34": "r36", "35": "r36", "36": "r36", "37": "r36", "38": "r36", "39": "r36", "40": "r36", "41": "r36", "42": "r36", "43": "r36", "44": "r36", "45": "r36", "46": "r36", "47": "r36", "48": "r36", "49": "r36", "50": "r36", "51": "r36", "52": "r36", "53": "r36", "54": "r36", "55": "r36", "56": "r36", "57": "r36", "58": "r36" }, { "10": 70, "18": 65, "19": 66, "21": 67, "22": 69, "24": "s28", "28": "s71", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "56": "r54", "58": "s68" }, { "10": 70, "18": 83, "19": 66, "21": 67, "22": 69, "24": "s28", "28": "s71", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "56": "r54", "58": "s68" }, { "23": "r47", "24": "r47", "25": "r47", "26": "r47", "27": "r47", "28": "r47", "29": "r47", "30": "r47", "31": "r47", "32": "r47", "33": "r47", "34": "r47", "35": "r47", "36": "r47", "37": "r47", "38": "r47", "39": "r47", "40": "r47", "41": "r47", "42": "r47", "43": "r47", "44": "r47", "45": "r47", "46": "r47", "47": "r47", "48": "r47", "49": "r47", "50": "r47", "51": "r47", "52": "r47", "53": "r47", "54": "r47", "55": "r47", "57": "r47" }, { "23": "r48", "24": "r48", "25": "r48", "26": "r48", "27": "r48", "28": "r48", "29": "r48", "30": "r48", "31": "r48", "32": "r48", "33": "r48", "34": "r48", "35": "r48", "36": "r48", "37": "r48", "38": "r48", "39": "r48", "40": "r48", "41": "r48", "42": "r48", "43": "r48", "44": "r48", "45": "r48", "46": "r48", "47": "r48", "48": "r48", "49": "r48", "50": "r48", "51": "r48", "52": "r48", "53": "r48", "54": "r48", "55": "r48", "57": "r48" }, { "4": 85, "5": 5, "6": 6, "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "31": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "4": 87, "5": 5, "6": 6, "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "31": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "4": 89, "5": 5, "6": 6, "24": "r10", "25": "r10", "26": "r10", "27": "r10", "28": "r10", "29": "r10", "30": "r10", "31": "r10", "32": "r10", "33": "r10", "34": "r10", "35": "r10", "36": "r10", "37": "r10", "38": "r10", "39": "r10", "40": "r10", "41": "r10", "42": "r10", "43": "r10", "44": "r10", "45": "r10", "52": "r10", "53": "r10", "54": "r10", "55": "r10", "57": "r10" }, { "23": "r13", "24": "r13", "25": "r13", "26": "r13", "27": "r13", "28": "r13", "29": "r13", "30": "r13", "31": "r13", "32": "r13", "33": "r13", "34": "r13", "35": "r13", "36": "r13", "37": "r13", "38": "r13", "39": "r13", "40": "r13", "41": "r13", "42": "r13", "43": "r13", "44": "r13", "45": "r13", "52": "r13", "53": "r13", "54": "r13", "55": "r13", "57": "r13" }, { "23": "r37", "24": "r37", "25": "r37", "26": "r37", "27": "r37", "28": "r37", "29": "r37", "30": "r37", "31": "r37", "32": "r37", "33": "r37", "34": "r37", "35": "r37", "36": "r37", "37": "r37", "38": "r37", "39": "r37", "40": "r37", "41": "r37", "42": "r37", "43": "r37", "44": "r37", "45": "r37", "52": "r37", "53": "r37", "54": "r37", "55": "r37", "57": "r37" }, { "23": "r39", "24": "r39", "25": "r39", "26": "r39", "27": "r39", "28": "r39", "29": "r39", "30": "r39", "31": "r39", "32": "r39", "33": "r39", "34": "r39", "35": "r39", "36": "r39", "37": "r39", "38": "r39", "39": "r39", "40": "r39", "41": "r39", "42": "r39", "43": "r39", "44": "r39", "45": "r39", "46": "s56", "52": "r39", "53": "r39", "54": "r39", "55": "r39", "57": "r39" }, { "23": "r41", "24": "r41", "25": "r41", "26": "r41", "27": "r41", "28": "r41", "29": "r41", "30": "r41", "31": "r41", "32": "r41", "33": "r41", "34": "r41", "35": "r41", "36": "r41", "37": "r41", "38": "r41", "39": "r41", "40": "r41", "41": "r41", "42": "r41", "43": "r41", "44": "r41", "45": "r41", "46": "r41", "52": "r41", "53": "r41", "54": "r41", "55": "r41", "57": "r41" }, { "23": "r42", "24": "r42", "25": "r42", "26": "r42", "27": "r42", "28": "r42", "29": "r42", "30": "r42", "31": "r42", "32": "r42", "33": "r42", "34": "r42", "35": "r42", "36": "r42", "37": "r42", "38": "r42", "39": "r42", "40": "r42", "41": "r42", "42": "r42", "43": "r42", "44": "r42", "45": "r42", "46": "r42", "52": "r42", "53": "r42", "54": "r42", "55": "r42", "57": "r42" }, { "23": "r43", "24": "r43", "25": "r43", "26": "r43", "27": "r43", "28": "r43", "29": "r43", "30": "r43", "31": "r43", "32": "r43", "33": "r43", "34": "r43", "35": "r43", "36": "r43", "37": "r43", "38": "r43", "39": "r43", "40": "r43", "41": "r43", "42": "r43", "43": "r43", "44": "r43", "45": "r43", "46": "r43", "52": "r43", "53": "r43", "54": "r43", "55": "r43", "57": "r43" }, { "23": "r44", "24": "r44", "25": "r44", "26": "r44", "27": "r44", "28": "r44", "29": "r44", "30": "r44", "31": "r44", "32": "r44", "33": "r44", "34": "r44", "35": "r44", "36": "r44", "37": "r44", "38": "r44", "39": "r44", "40": "r44", "41": "r44", "42": "r44", "43": "r44", "44": "r44", "45": "r44", "46": "r44", "52": "r44", "53": "r44", "54": "r44", "55": "r44", "57": "r44" }, { "23": "r45", "24": "r45", "25": "r45", "26": "r45", "27": "r45", "28": "r45", "29": "r45", "30": "r45", "31": "r45", "32": "r45", "33": "r45", "34": "r45", "35": "r45", "36": "r45", "37": "r45", "38": "r45", "39": "r45", "40": "r45", "41": "r45", "42": "r45", "43": "r45", "44": "r45", "45": "r45", "46": "r45", "52": "r45", "53": "r45", "54": "r45", "55": "r45", "57": "r45" }, { "23": "r46", "24": "r46", "25": "r46", "26": "r46", "27": "r46", "28": "r46", "29": "r46", "30": "r46", "31": "r46", "32": "r46", "33": "r46", "34": "r46", "35": "r46", "36": "r46", "37": "r46", "38": "r46", "39": "r46", "40": "r46", "41": "r46", "42": "r46", "43": "r46", "44": "r46", "45": "r46", "46": "r46", "52": "r46", "53": "r46", "54": "r46", "55": "r46", "57": "r46" }, { "23": "r40", "24": "r40", "25": "r40", "26": "r40", "27": "r40", "28": "r40", "29": "r40", "30": "r40", "31": "r40", "32": "r40", "33": "r40", "34": "r40", "35": "r40", "36": "r40", "37": "r40", "38": "r40", "39": "r40", "40": "r40", "41": "r40", "42": "r40", "43": "r40", "44": "r40", "45": "r40", "52": "r40", "53": "r40", "54": "r40", "55": "r40", "57": "r40" }, { "25": "s12", "31": "s58" }, { "23": "r18", "24": "r18", "25": "r18", "26": "r18", "27": "r18", "28": "r18", "29": "r18", "30": "r18", "31": "r18", "32": "r18", "33": "r18", "34": "r18", "35": "r18", "36": "r18", "37": "r18", "38": "r18", "39": "r18", "40": "r18", "41": "r18", "42": "r18", "43": "r18", "44": "r18", "45": "r18", "52": "r18", "53": "r18", "54": "r18", "55": "r18", "57": "r18" }, { "25": "s12", "31": "s60" }, { "23": "r19", "24": "r19", "25": "r19", "26": "r19", "27": "r19", "28": "r19", "29": "r19", "30": "r19", "31": "r19", "32": "r19", "33": "r19", "34": "r19", "35": "r19", "36": "r19", "37": "r19", "38": "r19", "39": "r19", "40": "r19", "41": "r19", "42": "r19", "43": "r19", "44": "r19", "45": "r19", "52": "r19", "53": "r19", "54": "r19", "55": "r19", "57": "r19" }, { "25": "s12", "31": "s62" }, { "23": "r20", "24": "r20", "25": "r20", "26": "r20", "27": "r20", "28": "r20", "29": "r20", "30": "r20", "31": "r20", "32": "r20", "33": "r20", "34": "r20", "35": "r20", "36": "r20", "37": "r20", "38": "r20", "39": "r20", "40": "r20", "41": "r20", "42": "r20", "43": "r20", "44": "r20", "45": "r20", "52": "r20", "53": "r20", "54": "r20", "55": "r20", "57": "r20" }, { "25": "s12", "31": "s64" }, { "23": "r21", "24": "r21", "25": "r21", "26": "r21", "27": "r21", "28": "r21", "29": "r21", "30": "r21", "31": "r21", "32": "r21", "33": "r21", "34": "r21", "35": "r21", "36": "r21", "37": "r21", "38": "r21", "39": "r21", "40": "r21", "41": "r21", "42": "r21", "43": "r21", "44": "r21", "45": "r21", "52": "r21", "53": "r21", "54": "r21", "55": "r21", "57": "r21" }, { "56": "s72" }, { "56": "r55" }, { "10": 70, "20": 73, "21": 75, "22": 76, "24": "s28", "28": "s71", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "56": "r56", "58": "s74" }, { "24": "r62", "28": "r62", "35": "r62", "36": "r62", "37": "r62", "38": "r62", "39": "r62", "40": "r62", "41": "r62", "42": "r62", "43": "r62", "44": "r62", "45": "r62", "56": "r62", "58": "r62" }, { "24": "r63", "28": "r63", "35": "r63", "36": "r63", "37": "r63", "38": "r63", "39": "r63", "40": "r63", "41": "r63", "42": "r63", "43": "r63", "44": "r63", "45": "r63", "56": "r63", "58": "r63" }, { "24": "r64", "28": "r64", "35": "r64", "36": "r64", "37": "r64", "38": "r64", "39": "r64", "40": "r64", "41": "r64", "42": "r64", "43": "r64", "44": "r64", "45": "r64", "56": "r64", "58": "r64" }, { "24": "r65", "28": "r65", "35": "r65", "36": "r65", "37": "r65", "38": "r65", "39": "r65", "40": "r65", "41": "r65", "42": "r65", "43": "r65", "44": "r65", "45": "r65", "56": "r65", "58": "r65" }, { "23": "r52", "24": "r52", "25": "r52", "26": "r52", "27": "r52", "28": "r52", "29": "r52", "30": "r52", "31": "r52", "32": "r52", "33": "r52", "34": "r52", "35": "r52", "36": "r52", "37": "r52", "38": "r52", "39": "r52", "40": "r52", "41": "r52", "42": "r52", "43": "r52", "44": "r52", "45": "r52", "46": "r52", "47": "r52", "48": "r52", "49": "r52", "50": "r52", "51": "r52", "52": "r52", "53": "r52", "54": "r52", "55": "r52", "57": "r52" }, { "56": "r57" }, { "10": 70, "21": 77, "22": 69, "24": "s28", "28": "s71", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "56": "r62", "58": "s68" }, { "56": "r59" }, { "10": 70, "20": 79, "21": 75, "22": 76, "24": "s28", "28": "s71", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "56": "r63", "58": "s80" }, { "10": 70, "18": 78, "19": 66, "21": 67, "22": 69, "24": "s28", "28": "s71", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "56": "r54", "58": "s68" }, { "56": "r58" }, { "56": "r60" }, { "10": 70, "21": 81, "22": 69, "24": "s28", "28": "s71", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "56": "r62", "58": "s68" }, { "10": 70, "18": 82, "19": 66, "21": 67, "22": 69, "24": "s28", "28": "s71", "35": "s29", "36": "s30", "37": "s31", "38": "s32", "39": "s33", "40": "s34", "41": "s35", "42": "s36", "43": "s37", "44": "s38", "45": "s39", "56": "r54", "58": "s68" }, { "56": "r61" }, { "56": "s84" }, { "23": "r53", "24": "r53", "25": "r53", "26": "r53", "27": "r53", "28": "r53", "29": "r53", "30": "r53", "31": "r53", "32": "r53", "33": "r53", "34": "r53", "35": "r53", "36": "r53", "37": "r53", "38": "r53", "39": "r53", "40": "r53", "41": "r53", "42": "r53", "43": "r53", "44": "r53", "45": "r53", "46": "r53", "47": "r53", "48": "r53", "49": "r53", "50": "r53", "51": "r53", "52": "r53", "53": "r53", "54": "r53", "55": "r53", "57": "r53" }, { "25": "s12", "31": "s86" }, { "23": "r49", "24": "r49", "25": "r49", "26": "r49", "27": "r49", "28": "r49", "29": "r49", "30": "r49", "31": "r49", "32": "r49", "33": "r49", "34": "r49", "35": "r49", "36": "r49", "37": "r49", "38": "r49", "39": "r49", "40": "r49", "41": "r49", "42": "r49", "43": "r49", "44": "r49", "45": "r49", "46": "r49", "47": "r49", "48": "r49", "49": "r49", "50": "r49", "51": "r49", "52": "r49", "53": "r49", "54": "r49", "55": "r49", "57": "r49" }, { "25": "s12", "31": "s88" }, { "23": "r50", "24": "r50", "25": "r50", "26": "r50", "27": "r50", "28": "r50", "29": "r50", "30": "r50", "31": "r50", "32": "r50", "33": "r50", "34": "r50", "35": "r50", "36": "r50", "37": "r50", "38": "r50", "39": "r50", "40": "r50", "41": "r50", "42": "r50", "43": "r50", "44": "r50", "45": "r50", "46": "r50", "47": "r50", "48": "r50", "49": "r50", "50": "r50", "51": "r50", "52": "r50", "53": "r50", "54": "r50", "55": "r50", "57": "r50" }, { "25": "s12", "31": "s90" }, { "23": "r51", "24": "r51", "25": "r51", "26": "r51", "27": "r51", "28": "r51", "29": "r51", "30": "r51", "31": "r51", "32": "r51", "33": "r51", "34": "r51", "35": "r51", "36": "r51", "37": "r51", "38": "r51", "39": "r51", "40": "r51", "41": "r51", "42": "r51", "43": "r51", "44": "r51", "45": "r51", "46": "r51", "47": "r51", "48": "r51", "49": "r51", "50": "r51", "51": "r51", "52": "r51", "53": "r51", "54": "r51", "55": "r51", "57": "r51" }];
    var stack = [];
    var tokenizer = void 0;
    var lexRules = [[/^#[^\n]+/, function() {
    }], [/^\s+/, function() {
    }], [/^-/, function() {
      return "DASH";
    }], [/^\//, function() {
      return "CHAR";
    }], [/^#/, function() {
      return "CHAR";
    }], [/^\|/, function() {
      return "CHAR";
    }], [/^\./, function() {
      return "CHAR";
    }], [/^\{/, function() {
      return "CHAR";
    }], [/^\{\d+\}/, function() {
      return "RANGE_EXACT";
    }], [/^\{\d+,\}/, function() {
      return "RANGE_OPEN";
    }], [/^\{\d+,\d+\}/, function() {
      return "RANGE_CLOSED";
    }], [/^\\k<(([\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0370-\u0374\u0376-\u0377\u037a-\u037d\u037f\u0386\u0388-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u048a-\u052f\u0531-\u0556\u0559\u0560-\u0588\u05d0-\u05ea\u05ef-\u05f2\u0620-\u064a\u066e-\u066f\u0671-\u06d3\u06d5\u06e5-\u06e6\u06ee-\u06ef\u06fa-\u06fc\u06ff\u0710\u0712-\u072f\u074d-\u07a5\u07b1\u07ca-\u07ea\u07f4-\u07f5\u07fa\u0800-\u0815\u081a\u0824\u0828\u0840-\u0858\u0860-\u086a\u08a0-\u08b4\u08b6-\u08bd\u0904-\u0939\u093d\u0950\u0958-\u0961\u0971-\u0980\u0985-\u098c\u098f-\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bd\u09ce\u09dc-\u09dd\u09df-\u09e1\u09f0-\u09f1\u09fc\u0a05-\u0a0a\u0a0f-\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32-\u0a33\u0a35-\u0a36\u0a38-\u0a39\u0a59-\u0a5c\u0a5e\u0a72-\u0a74\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2-\u0ab3\u0ab5-\u0ab9\u0abd\u0ad0\u0ae0-\u0ae1\u0af9\u0b05-\u0b0c\u0b0f-\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32-\u0b33\u0b35-\u0b39\u0b3d\u0b5c-\u0b5d\u0b5f-\u0b61\u0b71\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99-\u0b9a\u0b9c\u0b9e-\u0b9f\u0ba3-\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bd0\u0c05-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c39\u0c3d\u0c58-\u0c5a\u0c60-\u0c61\u0c80\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbd\u0cde\u0ce0-\u0ce1\u0cf1-\u0cf2\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d3a\u0d3d\u0d4e\u0d54-\u0d56\u0d5f-\u0d61\u0d7a-\u0d7f\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0e01-\u0e30\u0e32-\u0e33\u0e40-\u0e46\u0e81-\u0e82\u0e84\u0e86-\u0e8a\u0e8c-\u0ea3\u0ea5\u0ea7-\u0eb0\u0eb2-\u0eb3\u0ebd\u0ec0-\u0ec4\u0ec6\u0edc-\u0edf\u0f00\u0f40-\u0f47\u0f49-\u0f6c\u0f88-\u0f8c\u1000-\u102a\u103f\u1050-\u1055\u105a-\u105d\u1061\u1065-\u1066\u106e-\u1070\u1075-\u1081\u108e\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u1380-\u138f\u13a0-\u13f5\u13f8-\u13fd\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f8\u1700-\u170c\u170e-\u1711\u1720-\u1731\u1740-\u1751\u1760-\u176c\u176e-\u1770\u1780-\u17b3\u17d7\u17dc\u1820-\u1878\u1880-\u18a8\u18aa\u18b0-\u18f5\u1900-\u191e\u1950-\u196d\u1970-\u1974\u1980-\u19ab\u19b0-\u19c9\u1a00-\u1a16\u1a20-\u1a54\u1aa7\u1b05-\u1b33\u1b45-\u1b4b\u1b83-\u1ba0\u1bae-\u1baf\u1bba-\u1be5\u1c00-\u1c23\u1c4d-\u1c4f\u1c5a-\u1c7d\u1c80-\u1c88\u1c90-\u1cba\u1cbd-\u1cbf\u1ce9-\u1cec\u1cee-\u1cf3\u1cf5-\u1cf6\u1cfa\u1d00-\u1dbf\u1e00-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u2071\u207f\u2090-\u209c\u2102\u2107\u210a-\u2113\u2115\u2118-\u211d\u2124\u2126\u2128\u212a-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cee\u2cf2-\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d80-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u3005-\u3007\u3021-\u3029\u3031-\u3035\u3038-\u303c\u3041-\u3096\u309b-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312f\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fef\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua61f\ua62a-\ua62b\ua640-\ua66e\ua67f-\ua69d\ua6a0-\ua6ef\ua717-\ua71f\ua722-\ua788\ua78b-\ua7bf\ua7c2-\ua7c6\ua7f7-\ua801\ua803-\ua805\ua807-\ua80a\ua80c-\ua822\ua840-\ua873\ua882-\ua8b3\ua8f2-\ua8f7\ua8fb\ua8fd-\ua8fe\ua90a-\ua925\ua930-\ua946\ua960-\ua97c\ua984-\ua9b2\ua9cf\ua9e0-\ua9e4\ua9e6-\ua9ef\ua9fa-\ua9fe\uaa00-\uaa28\uaa40-\uaa42\uaa44-\uaa4b\uaa60-\uaa76\uaa7a\uaa7e-\uaaaf\uaab1\uaab5-\uaab6\uaab9-\uaabd\uaac0\uaac2\uaadb-\uaadd\uaae0-\uaaea\uaaf2-\uaaf4\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uab30-\uab5a\uab5c-\uab67\uab70-\uabe2\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d\ufb1f-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40-\ufb41\ufb43-\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe70-\ufe74\ufe76-\ufefc\uff21-\uff3a\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc]|\ud800[\udc00-\udc0b\udc0d-\udc26\udc28-\udc3a\udc3c-\udc3d\udc3f-\udc4d\udc50-\udc5d\udc80-\udcfa\udd40-\udd74\ude80-\ude9c\udea0-\uded0\udf00-\udf1f\udf2d-\udf4a\udf50-\udf75\udf80-\udf9d\udfa0-\udfc3\udfc8-\udfcf\udfd1-\udfd5]|\ud801[\udc00-\udc9d\udcb0-\udcd3\udcd8-\udcfb\udd00-\udd27\udd30-\udd63\ude00-\udf36\udf40-\udf55\udf60-\udf67]|\ud802[\udc00-\udc05\udc08\udc0a-\udc35\udc37-\udc38\udc3c\udc3f-\udc55\udc60-\udc76\udc80-\udc9e\udce0-\udcf2\udcf4-\udcf5\udd00-\udd15\udd20-\udd39\udd80-\uddb7\uddbe-\uddbf\ude00\ude10-\ude13\ude15-\ude17\ude19-\ude35\ude60-\ude7c\ude80-\ude9c\udec0-\udec7\udec9-\udee4\udf00-\udf35\udf40-\udf55\udf60-\udf72\udf80-\udf91]|\ud803[\udc00-\udc48\udc80-\udcb2\udcc0-\udcf2\udd00-\udd23\udf00-\udf1c\udf27\udf30-\udf45\udfe0-\udff6]|\ud804[\udc03-\udc37\udc83-\udcaf\udcd0-\udce8\udd03-\udd26\udd44\udd50-\udd72\udd76\udd83-\uddb2\uddc1-\uddc4\uddda\udddc\ude00-\ude11\ude13-\ude2b\ude80-\ude86\ude88\ude8a-\ude8d\ude8f-\ude9d\ude9f-\udea8\udeb0-\udede\udf05-\udf0c\udf0f-\udf10\udf13-\udf28\udf2a-\udf30\udf32-\udf33\udf35-\udf39\udf3d\udf50\udf5d-\udf61]|\ud805[\udc00-\udc34\udc47-\udc4a\udc5f\udc80-\udcaf\udcc4-\udcc5\udcc7\udd80-\uddae\uddd8-\udddb\ude00-\ude2f\ude44\ude80-\udeaa\udeb8\udf00-\udf1a]|\ud806[\udc00-\udc2b\udca0-\udcdf\udcff\udda0-\udda7\uddaa-\uddd0\udde1\udde3\ude00\ude0b-\ude32\ude3a\ude50\ude5c-\ude89\ude9d\udec0-\udef8]|\ud807[\udc00-\udc08\udc0a-\udc2e\udc40\udc72-\udc8f\udd00-\udd06\udd08-\udd09\udd0b-\udd30\udd46\udd60-\udd65\udd67-\udd68\udd6a-\udd89\udd98\udee0-\udef2]|\ud808[\udc00-\udf99]|\ud809[\udc00-\udc6e\udc80-\udd43]|\ud80c[\udc00-\udfff]|\ud80d[\udc00-\udc2e]|\ud811[\udc00-\ude46]|\ud81a[\udc00-\ude38\ude40-\ude5e\uded0-\udeed\udf00-\udf2f\udf40-\udf43\udf63-\udf77\udf7d-\udf8f]|\ud81b[\ude40-\ude7f\udf00-\udf4a\udf50\udf93-\udf9f\udfe0-\udfe1\udfe3]|\ud81c[\udc00-\udfff]|\ud81d[\udc00-\udfff]|\ud81e[\udc00-\udfff]|\ud81f[\udc00-\udfff]|\ud820[\udc00-\udfff]|\ud821[\udc00-\udff7]|\ud822[\udc00-\udef2]|\ud82c[\udc00-\udd1e\udd50-\udd52\udd64-\udd67\udd70-\udefb]|\ud82f[\udc00-\udc6a\udc70-\udc7c\udc80-\udc88\udc90-\udc99]|\ud835[\udc00-\udc54\udc56-\udc9c\udc9e-\udc9f\udca2\udca5-\udca6\udca9-\udcac\udcae-\udcb9\udcbb\udcbd-\udcc3\udcc5-\udd05\udd07-\udd0a\udd0d-\udd14\udd16-\udd1c\udd1e-\udd39\udd3b-\udd3e\udd40-\udd44\udd46\udd4a-\udd50\udd52-\udea5\udea8-\udec0\udec2-\udeda\udedc-\udefa\udefc-\udf14\udf16-\udf34\udf36-\udf4e\udf50-\udf6e\udf70-\udf88\udf8a-\udfa8\udfaa-\udfc2\udfc4-\udfcb]|\ud838[\udd00-\udd2c\udd37-\udd3d\udd4e\udec0-\udeeb]|\ud83a[\udc00-\udcc4\udd00-\udd43\udd4b]|\ud83b[\ude00-\ude03\ude05-\ude1f\ude21-\ude22\ude24\ude27\ude29-\ude32\ude34-\ude37\ude39\ude3b\ude42\ude47\ude49\ude4b\ude4d-\ude4f\ude51-\ude52\ude54\ude57\ude59\ude5b\ude5d\ude5f\ude61-\ude62\ude64\ude67-\ude6a\ude6c-\ude72\ude74-\ude77\ude79-\ude7c\ude7e\ude80-\ude89\ude8b-\ude9b\udea1-\udea3\udea5-\udea9\udeab-\udebb]|\ud840[\udc00-\udfff]|\ud841[\udc00-\udfff]|\ud842[\udc00-\udfff]|\ud843[\udc00-\udfff]|\ud844[\udc00-\udfff]|\ud845[\udc00-\udfff]|\ud846[\udc00-\udfff]|\ud847[\udc00-\udfff]|\ud848[\udc00-\udfff]|\ud849[\udc00-\udfff]|\ud84a[\udc00-\udfff]|\ud84b[\udc00-\udfff]|\ud84c[\udc00-\udfff]|\ud84d[\udc00-\udfff]|\ud84e[\udc00-\udfff]|\ud84f[\udc00-\udfff]|\ud850[\udc00-\udfff]|\ud851[\udc00-\udfff]|\ud852[\udc00-\udfff]|\ud853[\udc00-\udfff]|\ud854[\udc00-\udfff]|\ud855[\udc00-\udfff]|\ud856[\udc00-\udfff]|\ud857[\udc00-\udfff]|\ud858[\udc00-\udfff]|\ud859[\udc00-\udfff]|\ud85a[\udc00-\udfff]|\ud85b[\udc00-\udfff]|\ud85c[\udc00-\udfff]|\ud85d[\udc00-\udfff]|\ud85e[\udc00-\udfff]|\ud85f[\udc00-\udfff]|\ud860[\udc00-\udfff]|\ud861[\udc00-\udfff]|\ud862[\udc00-\udfff]|\ud863[\udc00-\udfff]|\ud864[\udc00-\udfff]|\ud865[\udc00-\udfff]|\ud866[\udc00-\udfff]|\ud867[\udc00-\udfff]|\ud868[\udc00-\udfff]|\ud869[\udc00-\uded6\udf00-\udfff]|\ud86a[\udc00-\udfff]|\ud86b[\udc00-\udfff]|\ud86c[\udc00-\udfff]|\ud86d[\udc00-\udf34\udf40-\udfff]|\ud86e[\udc00-\udc1d\udc20-\udfff]|\ud86f[\udc00-\udfff]|\ud870[\udc00-\udfff]|\ud871[\udc00-\udfff]|\ud872[\udc00-\udfff]|\ud873[\udc00-\udea1\udeb0-\udfff]|\ud874[\udc00-\udfff]|\ud875[\udc00-\udfff]|\ud876[\udc00-\udfff]|\ud877[\udc00-\udfff]|\ud878[\udc00-\udfff]|\ud879[\udc00-\udfff]|\ud87a[\udc00-\udfe0]|\ud87e[\udc00-\ude1d])|[$_]|(\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,}\}))(([\u0030-\u0039\u0041-\u005a\u005f\u0061-\u007a\u00aa\u00b5\u00b7\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0300-\u0374\u0376-\u0377\u037a-\u037d\u037f\u0386-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u0483-\u0487\u048a-\u052f\u0531-\u0556\u0559\u0560-\u0588\u0591-\u05bd\u05bf\u05c1-\u05c2\u05c4-\u05c5\u05c7\u05d0-\u05ea\u05ef-\u05f2\u0610-\u061a\u0620-\u0669\u066e-\u06d3\u06d5-\u06dc\u06df-\u06e8\u06ea-\u06fc\u06ff\u0710-\u074a\u074d-\u07b1\u07c0-\u07f5\u07fa\u07fd\u0800-\u082d\u0840-\u085b\u0860-\u086a\u08a0-\u08b4\u08b6-\u08bd\u08d3-\u08e1\u08e3-\u0963\u0966-\u096f\u0971-\u0983\u0985-\u098c\u098f-\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bc-\u09c4\u09c7-\u09c8\u09cb-\u09ce\u09d7\u09dc-\u09dd\u09df-\u09e3\u09e6-\u09f1\u09fc\u09fe\u0a01-\u0a03\u0a05-\u0a0a\u0a0f-\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32-\u0a33\u0a35-\u0a36\u0a38-\u0a39\u0a3c\u0a3e-\u0a42\u0a47-\u0a48\u0a4b-\u0a4d\u0a51\u0a59-\u0a5c\u0a5e\u0a66-\u0a75\u0a81-\u0a83\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2-\u0ab3\u0ab5-\u0ab9\u0abc-\u0ac5\u0ac7-\u0ac9\u0acb-\u0acd\u0ad0\u0ae0-\u0ae3\u0ae6-\u0aef\u0af9-\u0aff\u0b01-\u0b03\u0b05-\u0b0c\u0b0f-\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32-\u0b33\u0b35-\u0b39\u0b3c-\u0b44\u0b47-\u0b48\u0b4b-\u0b4d\u0b56-\u0b57\u0b5c-\u0b5d\u0b5f-\u0b63\u0b66-\u0b6f\u0b71\u0b82-\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99-\u0b9a\u0b9c\u0b9e-\u0b9f\u0ba3-\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bbe-\u0bc2\u0bc6-\u0bc8\u0bca-\u0bcd\u0bd0\u0bd7\u0be6-\u0bef\u0c00-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c39\u0c3d-\u0c44\u0c46-\u0c48\u0c4a-\u0c4d\u0c55-\u0c56\u0c58-\u0c5a\u0c60-\u0c63\u0c66-\u0c6f\u0c80-\u0c83\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbc-\u0cc4\u0cc6-\u0cc8\u0cca-\u0ccd\u0cd5-\u0cd6\u0cde\u0ce0-\u0ce3\u0ce6-\u0cef\u0cf1-\u0cf2\u0d00-\u0d03\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d44\u0d46-\u0d48\u0d4a-\u0d4e\u0d54-\u0d57\u0d5f-\u0d63\u0d66-\u0d6f\u0d7a-\u0d7f\u0d82-\u0d83\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0dca\u0dcf-\u0dd4\u0dd6\u0dd8-\u0ddf\u0de6-\u0def\u0df2-\u0df3\u0e01-\u0e3a\u0e40-\u0e4e\u0e50-\u0e59\u0e81-\u0e82\u0e84\u0e86-\u0e8a\u0e8c-\u0ea3\u0ea5\u0ea7-\u0ebd\u0ec0-\u0ec4\u0ec6\u0ec8-\u0ecd\u0ed0-\u0ed9\u0edc-\u0edf\u0f00\u0f18-\u0f19\u0f20-\u0f29\u0f35\u0f37\u0f39\u0f3e-\u0f47\u0f49-\u0f6c\u0f71-\u0f84\u0f86-\u0f97\u0f99-\u0fbc\u0fc6\u1000-\u1049\u1050-\u109d\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u135d-\u135f\u1369-\u1371\u1380-\u138f\u13a0-\u13f5\u13f8-\u13fd\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f8\u1700-\u170c\u170e-\u1714\u1720-\u1734\u1740-\u1753\u1760-\u176c\u176e-\u1770\u1772-\u1773\u1780-\u17d3\u17d7\u17dc-\u17dd\u17e0-\u17e9\u180b-\u180d\u1810-\u1819\u1820-\u1878\u1880-\u18aa\u18b0-\u18f5\u1900-\u191e\u1920-\u192b\u1930-\u193b\u1946-\u196d\u1970-\u1974\u1980-\u19ab\u19b0-\u19c9\u19d0-\u19da\u1a00-\u1a1b\u1a20-\u1a5e\u1a60-\u1a7c\u1a7f-\u1a89\u1a90-\u1a99\u1aa7\u1ab0-\u1abd\u1b00-\u1b4b\u1b50-\u1b59\u1b6b-\u1b73\u1b80-\u1bf3\u1c00-\u1c37\u1c40-\u1c49\u1c4d-\u1c7d\u1c80-\u1c88\u1c90-\u1cba\u1cbd-\u1cbf\u1cd0-\u1cd2\u1cd4-\u1cfa\u1d00-\u1df9\u1dfb-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u203f-\u2040\u2054\u2071\u207f\u2090-\u209c\u20d0-\u20dc\u20e1\u20e5-\u20f0\u2102\u2107\u210a-\u2113\u2115\u2118-\u211d\u2124\u2126\u2128\u212a-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d7f-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u2de0-\u2dff\u3005-\u3007\u3021-\u302f\u3031-\u3035\u3038-\u303c\u3041-\u3096\u3099-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312f\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fef\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua62b\ua640-\ua66f\ua674-\ua67d\ua67f-\ua6f1\ua717-\ua71f\ua722-\ua788\ua78b-\ua7bf\ua7c2-\ua7c6\ua7f7-\ua827\ua840-\ua873\ua880-\ua8c5\ua8d0-\ua8d9\ua8e0-\ua8f7\ua8fb\ua8fd-\ua92d\ua930-\ua953\ua960-\ua97c\ua980-\ua9c0\ua9cf-\ua9d9\ua9e0-\ua9fe\uaa00-\uaa36\uaa40-\uaa4d\uaa50-\uaa59\uaa60-\uaa76\uaa7a-\uaac2\uaadb-\uaadd\uaae0-\uaaef\uaaf2-\uaaf6\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uab30-\uab5a\uab5c-\uab67\uab70-\uabea\uabec-\uabed\uabf0-\uabf9\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40-\ufb41\ufb43-\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe00-\ufe0f\ufe20-\ufe2f\ufe33-\ufe34\ufe4d-\ufe4f\ufe70-\ufe74\ufe76-\ufefc\uff10-\uff19\uff21-\uff3a\uff3f\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc]|\ud800[\udc00-\udc0b\udc0d-\udc26\udc28-\udc3a\udc3c-\udc3d\udc3f-\udc4d\udc50-\udc5d\udc80-\udcfa\udd40-\udd74\uddfd\ude80-\ude9c\udea0-\uded0\udee0\udf00-\udf1f\udf2d-\udf4a\udf50-\udf7a\udf80-\udf9d\udfa0-\udfc3\udfc8-\udfcf\udfd1-\udfd5]|\ud801[\udc00-\udc9d\udca0-\udca9\udcb0-\udcd3\udcd8-\udcfb\udd00-\udd27\udd30-\udd63\ude00-\udf36\udf40-\udf55\udf60-\udf67]|\ud802[\udc00-\udc05\udc08\udc0a-\udc35\udc37-\udc38\udc3c\udc3f-\udc55\udc60-\udc76\udc80-\udc9e\udce0-\udcf2\udcf4-\udcf5\udd00-\udd15\udd20-\udd39\udd80-\uddb7\uddbe-\uddbf\ude00-\ude03\ude05-\ude06\ude0c-\ude13\ude15-\ude17\ude19-\ude35\ude38-\ude3a\ude3f\ude60-\ude7c\ude80-\ude9c\udec0-\udec7\udec9-\udee6\udf00-\udf35\udf40-\udf55\udf60-\udf72\udf80-\udf91]|\ud803[\udc00-\udc48\udc80-\udcb2\udcc0-\udcf2\udd00-\udd27\udd30-\udd39\udf00-\udf1c\udf27\udf30-\udf50\udfe0-\udff6]|\ud804[\udc00-\udc46\udc66-\udc6f\udc7f-\udcba\udcd0-\udce8\udcf0-\udcf9\udd00-\udd34\udd36-\udd3f\udd44-\udd46\udd50-\udd73\udd76\udd80-\uddc4\uddc9-\uddcc\uddd0-\uddda\udddc\ude00-\ude11\ude13-\ude37\ude3e\ude80-\ude86\ude88\ude8a-\ude8d\ude8f-\ude9d\ude9f-\udea8\udeb0-\udeea\udef0-\udef9\udf00-\udf03\udf05-\udf0c\udf0f-\udf10\udf13-\udf28\udf2a-\udf30\udf32-\udf33\udf35-\udf39\udf3b-\udf44\udf47-\udf48\udf4b-\udf4d\udf50\udf57\udf5d-\udf63\udf66-\udf6c\udf70-\udf74]|\ud805[\udc00-\udc4a\udc50-\udc59\udc5e-\udc5f\udc80-\udcc5\udcc7\udcd0-\udcd9\udd80-\uddb5\uddb8-\uddc0\uddd8-\udddd\ude00-\ude40\ude44\ude50-\ude59\ude80-\udeb8\udec0-\udec9\udf00-\udf1a\udf1d-\udf2b\udf30-\udf39]|\ud806[\udc00-\udc3a\udca0-\udce9\udcff\udda0-\udda7\uddaa-\uddd7\uddda-\udde1\udde3-\udde4\ude00-\ude3e\ude47\ude50-\ude99\ude9d\udec0-\udef8]|\ud807[\udc00-\udc08\udc0a-\udc36\udc38-\udc40\udc50-\udc59\udc72-\udc8f\udc92-\udca7\udca9-\udcb6\udd00-\udd06\udd08-\udd09\udd0b-\udd36\udd3a\udd3c-\udd3d\udd3f-\udd47\udd50-\udd59\udd60-\udd65\udd67-\udd68\udd6a-\udd8e\udd90-\udd91\udd93-\udd98\udda0-\udda9\udee0-\udef6]|\ud808[\udc00-\udf99]|\ud809[\udc00-\udc6e\udc80-\udd43]|\ud80c[\udc00-\udfff]|\ud80d[\udc00-\udc2e]|\ud811[\udc00-\ude46]|\ud81a[\udc00-\ude38\ude40-\ude5e\ude60-\ude69\uded0-\udeed\udef0-\udef4\udf00-\udf36\udf40-\udf43\udf50-\udf59\udf63-\udf77\udf7d-\udf8f]|\ud81b[\ude40-\ude7f\udf00-\udf4a\udf4f-\udf87\udf8f-\udf9f\udfe0-\udfe1\udfe3]|\ud81c[\udc00-\udfff]|\ud81d[\udc00-\udfff]|\ud81e[\udc00-\udfff]|\ud81f[\udc00-\udfff]|\ud820[\udc00-\udfff]|\ud821[\udc00-\udff7]|\ud822[\udc00-\udef2]|\ud82c[\udc00-\udd1e\udd50-\udd52\udd64-\udd67\udd70-\udefb]|\ud82f[\udc00-\udc6a\udc70-\udc7c\udc80-\udc88\udc90-\udc99\udc9d-\udc9e]|\ud834[\udd65-\udd69\udd6d-\udd72\udd7b-\udd82\udd85-\udd8b\uddaa-\uddad\ude42-\ude44]|\ud835[\udc00-\udc54\udc56-\udc9c\udc9e-\udc9f\udca2\udca5-\udca6\udca9-\udcac\udcae-\udcb9\udcbb\udcbd-\udcc3\udcc5-\udd05\udd07-\udd0a\udd0d-\udd14\udd16-\udd1c\udd1e-\udd39\udd3b-\udd3e\udd40-\udd44\udd46\udd4a-\udd50\udd52-\udea5\udea8-\udec0\udec2-\udeda\udedc-\udefa\udefc-\udf14\udf16-\udf34\udf36-\udf4e\udf50-\udf6e\udf70-\udf88\udf8a-\udfa8\udfaa-\udfc2\udfc4-\udfcb\udfce-\udfff]|\ud836[\ude00-\ude36\ude3b-\ude6c\ude75\ude84\ude9b-\ude9f\udea1-\udeaf]|\ud838[\udc00-\udc06\udc08-\udc18\udc1b-\udc21\udc23-\udc24\udc26-\udc2a\udd00-\udd2c\udd30-\udd3d\udd40-\udd49\udd4e\udec0-\udef9]|\ud83a[\udc00-\udcc4\udcd0-\udcd6\udd00-\udd4b\udd50-\udd59]|\ud83b[\ude00-\ude03\ude05-\ude1f\ude21-\ude22\ude24\ude27\ude29-\ude32\ude34-\ude37\ude39\ude3b\ude42\ude47\ude49\ude4b\ude4d-\ude4f\ude51-\ude52\ude54\ude57\ude59\ude5b\ude5d\ude5f\ude61-\ude62\ude64\ude67-\ude6a\ude6c-\ude72\ude74-\ude77\ude79-\ude7c\ude7e\ude80-\ude89\ude8b-\ude9b\udea1-\udea3\udea5-\udea9\udeab-\udebb]|\ud840[\udc00-\udfff]|\ud841[\udc00-\udfff]|\ud842[\udc00-\udfff]|\ud843[\udc00-\udfff]|\ud844[\udc00-\udfff]|\ud845[\udc00-\udfff]|\ud846[\udc00-\udfff]|\ud847[\udc00-\udfff]|\ud848[\udc00-\udfff]|\ud849[\udc00-\udfff]|\ud84a[\udc00-\udfff]|\ud84b[\udc00-\udfff]|\ud84c[\udc00-\udfff]|\ud84d[\udc00-\udfff]|\ud84e[\udc00-\udfff]|\ud84f[\udc00-\udfff]|\ud850[\udc00-\udfff]|\ud851[\udc00-\udfff]|\ud852[\udc00-\udfff]|\ud853[\udc00-\udfff]|\ud854[\udc00-\udfff]|\ud855[\udc00-\udfff]|\ud856[\udc00-\udfff]|\ud857[\udc00-\udfff]|\ud858[\udc00-\udfff]|\ud859[\udc00-\udfff]|\ud85a[\udc00-\udfff]|\ud85b[\udc00-\udfff]|\ud85c[\udc00-\udfff]|\ud85d[\udc00-\udfff]|\ud85e[\udc00-\udfff]|\ud85f[\udc00-\udfff]|\ud860[\udc00-\udfff]|\ud861[\udc00-\udfff]|\ud862[\udc00-\udfff]|\ud863[\udc00-\udfff]|\ud864[\udc00-\udfff]|\ud865[\udc00-\udfff]|\ud866[\udc00-\udfff]|\ud867[\udc00-\udfff]|\ud868[\udc00-\udfff]|\ud869[\udc00-\uded6\udf00-\udfff]|\ud86a[\udc00-\udfff]|\ud86b[\udc00-\udfff]|\ud86c[\udc00-\udfff]|\ud86d[\udc00-\udf34\udf40-\udfff]|\ud86e[\udc00-\udc1d\udc20-\udfff]|\ud86f[\udc00-\udfff]|\ud870[\udc00-\udfff]|\ud871[\udc00-\udfff]|\ud872[\udc00-\udfff]|\ud873[\udc00-\udea1\udeb0-\udfff]|\ud874[\udc00-\udfff]|\ud875[\udc00-\udfff]|\ud876[\udc00-\udfff]|\ud877[\udc00-\udfff]|\ud878[\udc00-\udfff]|\ud879[\udc00-\udfff]|\ud87a[\udc00-\udfe0]|\ud87e[\udc00-\ude1d]|\udb40[\udd00-\uddef])|[$_]|(\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,}\})|[\u200c\u200d])*>/, function() {
      var groupName = yytext.slice(3, -1);
      validateUnicodeGroupName(groupName, this.getCurrentState());
      return "NAMED_GROUP_REF";
    }], [/^\\b/, function() {
      return "ESC_b";
    }], [/^\\B/, function() {
      return "ESC_B";
    }], [/^\\c[a-zA-Z]/, function() {
      return "CTRL_CH";
    }], [/^\\0\d{1,2}/, function() {
      return "OCT_CODE";
    }], [/^\\0/, function() {
      return "DEC_CODE";
    }], [/^\\\d{1,3}/, function() {
      return "DEC_CODE";
    }], [/^\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}/, function() {
      return "U_CODE_SURROGATE";
    }], [/^\\u\{[0-9a-fA-F]{1,}\}/, function() {
      return "U_CODE";
    }], [/^\\u[0-9a-fA-F]{4}/, function() {
      return "U_CODE";
    }], [/^\\[pP]\{\w+(?:=\w+)?\}/, function() {
      return "U_PROP_VALUE_EXP";
    }], [/^\\x[0-9a-fA-F]{2}/, function() {
      return "HEX_CODE";
    }], [/^\\[tnrdDsSwWvf]/, function() {
      return "META_CHAR";
    }], [/^\\\//, function() {
      return "ESC_CHAR";
    }], [/^\\[ #]/, function() {
      return "ESC_CHAR";
    }], [/^\\[\^\$\.\*\+\?\(\)\\\[\]\{\}\|\/]/, function() {
      return "ESC_CHAR";
    }], [/^\\[^*?+\[()\\|]/, function() {
      var s = this.getCurrentState();
      if (s === "u_class" && yytext === "\\-") {
        return "ESC_CHAR";
      } else if (s === "u" || s === "xu" || s === "u_class") {
        throw new SyntaxError("invalid Unicode escape " + yytext);
      }
      return "ESC_CHAR";
    }], [/^\(/, function() {
      return "CHAR";
    }], [/^\)/, function() {
      return "CHAR";
    }], [/^\(\?=/, function() {
      return "POS_LA_ASSERT";
    }], [/^\(\?!/, function() {
      return "NEG_LA_ASSERT";
    }], [/^\(\?<=/, function() {
      return "POS_LB_ASSERT";
    }], [/^\(\?<!/, function() {
      return "NEG_LB_ASSERT";
    }], [/^\(\?:/, function() {
      return "NON_CAPTURE_GROUP";
    }], [/^\(\?<(([\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0370-\u0374\u0376-\u0377\u037a-\u037d\u037f\u0386\u0388-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u048a-\u052f\u0531-\u0556\u0559\u0560-\u0588\u05d0-\u05ea\u05ef-\u05f2\u0620-\u064a\u066e-\u066f\u0671-\u06d3\u06d5\u06e5-\u06e6\u06ee-\u06ef\u06fa-\u06fc\u06ff\u0710\u0712-\u072f\u074d-\u07a5\u07b1\u07ca-\u07ea\u07f4-\u07f5\u07fa\u0800-\u0815\u081a\u0824\u0828\u0840-\u0858\u0860-\u086a\u08a0-\u08b4\u08b6-\u08bd\u0904-\u0939\u093d\u0950\u0958-\u0961\u0971-\u0980\u0985-\u098c\u098f-\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bd\u09ce\u09dc-\u09dd\u09df-\u09e1\u09f0-\u09f1\u09fc\u0a05-\u0a0a\u0a0f-\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32-\u0a33\u0a35-\u0a36\u0a38-\u0a39\u0a59-\u0a5c\u0a5e\u0a72-\u0a74\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2-\u0ab3\u0ab5-\u0ab9\u0abd\u0ad0\u0ae0-\u0ae1\u0af9\u0b05-\u0b0c\u0b0f-\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32-\u0b33\u0b35-\u0b39\u0b3d\u0b5c-\u0b5d\u0b5f-\u0b61\u0b71\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99-\u0b9a\u0b9c\u0b9e-\u0b9f\u0ba3-\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bd0\u0c05-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c39\u0c3d\u0c58-\u0c5a\u0c60-\u0c61\u0c80\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbd\u0cde\u0ce0-\u0ce1\u0cf1-\u0cf2\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d3a\u0d3d\u0d4e\u0d54-\u0d56\u0d5f-\u0d61\u0d7a-\u0d7f\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0e01-\u0e30\u0e32-\u0e33\u0e40-\u0e46\u0e81-\u0e82\u0e84\u0e86-\u0e8a\u0e8c-\u0ea3\u0ea5\u0ea7-\u0eb0\u0eb2-\u0eb3\u0ebd\u0ec0-\u0ec4\u0ec6\u0edc-\u0edf\u0f00\u0f40-\u0f47\u0f49-\u0f6c\u0f88-\u0f8c\u1000-\u102a\u103f\u1050-\u1055\u105a-\u105d\u1061\u1065-\u1066\u106e-\u1070\u1075-\u1081\u108e\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u1380-\u138f\u13a0-\u13f5\u13f8-\u13fd\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f8\u1700-\u170c\u170e-\u1711\u1720-\u1731\u1740-\u1751\u1760-\u176c\u176e-\u1770\u1780-\u17b3\u17d7\u17dc\u1820-\u1878\u1880-\u18a8\u18aa\u18b0-\u18f5\u1900-\u191e\u1950-\u196d\u1970-\u1974\u1980-\u19ab\u19b0-\u19c9\u1a00-\u1a16\u1a20-\u1a54\u1aa7\u1b05-\u1b33\u1b45-\u1b4b\u1b83-\u1ba0\u1bae-\u1baf\u1bba-\u1be5\u1c00-\u1c23\u1c4d-\u1c4f\u1c5a-\u1c7d\u1c80-\u1c88\u1c90-\u1cba\u1cbd-\u1cbf\u1ce9-\u1cec\u1cee-\u1cf3\u1cf5-\u1cf6\u1cfa\u1d00-\u1dbf\u1e00-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u2071\u207f\u2090-\u209c\u2102\u2107\u210a-\u2113\u2115\u2118-\u211d\u2124\u2126\u2128\u212a-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cee\u2cf2-\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d80-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u3005-\u3007\u3021-\u3029\u3031-\u3035\u3038-\u303c\u3041-\u3096\u309b-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312f\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fef\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua61f\ua62a-\ua62b\ua640-\ua66e\ua67f-\ua69d\ua6a0-\ua6ef\ua717-\ua71f\ua722-\ua788\ua78b-\ua7bf\ua7c2-\ua7c6\ua7f7-\ua801\ua803-\ua805\ua807-\ua80a\ua80c-\ua822\ua840-\ua873\ua882-\ua8b3\ua8f2-\ua8f7\ua8fb\ua8fd-\ua8fe\ua90a-\ua925\ua930-\ua946\ua960-\ua97c\ua984-\ua9b2\ua9cf\ua9e0-\ua9e4\ua9e6-\ua9ef\ua9fa-\ua9fe\uaa00-\uaa28\uaa40-\uaa42\uaa44-\uaa4b\uaa60-\uaa76\uaa7a\uaa7e-\uaaaf\uaab1\uaab5-\uaab6\uaab9-\uaabd\uaac0\uaac2\uaadb-\uaadd\uaae0-\uaaea\uaaf2-\uaaf4\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uab30-\uab5a\uab5c-\uab67\uab70-\uabe2\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d\ufb1f-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40-\ufb41\ufb43-\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe70-\ufe74\ufe76-\ufefc\uff21-\uff3a\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc]|\ud800[\udc00-\udc0b\udc0d-\udc26\udc28-\udc3a\udc3c-\udc3d\udc3f-\udc4d\udc50-\udc5d\udc80-\udcfa\udd40-\udd74\ude80-\ude9c\udea0-\uded0\udf00-\udf1f\udf2d-\udf4a\udf50-\udf75\udf80-\udf9d\udfa0-\udfc3\udfc8-\udfcf\udfd1-\udfd5]|\ud801[\udc00-\udc9d\udcb0-\udcd3\udcd8-\udcfb\udd00-\udd27\udd30-\udd63\ude00-\udf36\udf40-\udf55\udf60-\udf67]|\ud802[\udc00-\udc05\udc08\udc0a-\udc35\udc37-\udc38\udc3c\udc3f-\udc55\udc60-\udc76\udc80-\udc9e\udce0-\udcf2\udcf4-\udcf5\udd00-\udd15\udd20-\udd39\udd80-\uddb7\uddbe-\uddbf\ude00\ude10-\ude13\ude15-\ude17\ude19-\ude35\ude60-\ude7c\ude80-\ude9c\udec0-\udec7\udec9-\udee4\udf00-\udf35\udf40-\udf55\udf60-\udf72\udf80-\udf91]|\ud803[\udc00-\udc48\udc80-\udcb2\udcc0-\udcf2\udd00-\udd23\udf00-\udf1c\udf27\udf30-\udf45\udfe0-\udff6]|\ud804[\udc03-\udc37\udc83-\udcaf\udcd0-\udce8\udd03-\udd26\udd44\udd50-\udd72\udd76\udd83-\uddb2\uddc1-\uddc4\uddda\udddc\ude00-\ude11\ude13-\ude2b\ude80-\ude86\ude88\ude8a-\ude8d\ude8f-\ude9d\ude9f-\udea8\udeb0-\udede\udf05-\udf0c\udf0f-\udf10\udf13-\udf28\udf2a-\udf30\udf32-\udf33\udf35-\udf39\udf3d\udf50\udf5d-\udf61]|\ud805[\udc00-\udc34\udc47-\udc4a\udc5f\udc80-\udcaf\udcc4-\udcc5\udcc7\udd80-\uddae\uddd8-\udddb\ude00-\ude2f\ude44\ude80-\udeaa\udeb8\udf00-\udf1a]|\ud806[\udc00-\udc2b\udca0-\udcdf\udcff\udda0-\udda7\uddaa-\uddd0\udde1\udde3\ude00\ude0b-\ude32\ude3a\ude50\ude5c-\ude89\ude9d\udec0-\udef8]|\ud807[\udc00-\udc08\udc0a-\udc2e\udc40\udc72-\udc8f\udd00-\udd06\udd08-\udd09\udd0b-\udd30\udd46\udd60-\udd65\udd67-\udd68\udd6a-\udd89\udd98\udee0-\udef2]|\ud808[\udc00-\udf99]|\ud809[\udc00-\udc6e\udc80-\udd43]|\ud80c[\udc00-\udfff]|\ud80d[\udc00-\udc2e]|\ud811[\udc00-\ude46]|\ud81a[\udc00-\ude38\ude40-\ude5e\uded0-\udeed\udf00-\udf2f\udf40-\udf43\udf63-\udf77\udf7d-\udf8f]|\ud81b[\ude40-\ude7f\udf00-\udf4a\udf50\udf93-\udf9f\udfe0-\udfe1\udfe3]|\ud81c[\udc00-\udfff]|\ud81d[\udc00-\udfff]|\ud81e[\udc00-\udfff]|\ud81f[\udc00-\udfff]|\ud820[\udc00-\udfff]|\ud821[\udc00-\udff7]|\ud822[\udc00-\udef2]|\ud82c[\udc00-\udd1e\udd50-\udd52\udd64-\udd67\udd70-\udefb]|\ud82f[\udc00-\udc6a\udc70-\udc7c\udc80-\udc88\udc90-\udc99]|\ud835[\udc00-\udc54\udc56-\udc9c\udc9e-\udc9f\udca2\udca5-\udca6\udca9-\udcac\udcae-\udcb9\udcbb\udcbd-\udcc3\udcc5-\udd05\udd07-\udd0a\udd0d-\udd14\udd16-\udd1c\udd1e-\udd39\udd3b-\udd3e\udd40-\udd44\udd46\udd4a-\udd50\udd52-\udea5\udea8-\udec0\udec2-\udeda\udedc-\udefa\udefc-\udf14\udf16-\udf34\udf36-\udf4e\udf50-\udf6e\udf70-\udf88\udf8a-\udfa8\udfaa-\udfc2\udfc4-\udfcb]|\ud838[\udd00-\udd2c\udd37-\udd3d\udd4e\udec0-\udeeb]|\ud83a[\udc00-\udcc4\udd00-\udd43\udd4b]|\ud83b[\ude00-\ude03\ude05-\ude1f\ude21-\ude22\ude24\ude27\ude29-\ude32\ude34-\ude37\ude39\ude3b\ude42\ude47\ude49\ude4b\ude4d-\ude4f\ude51-\ude52\ude54\ude57\ude59\ude5b\ude5d\ude5f\ude61-\ude62\ude64\ude67-\ude6a\ude6c-\ude72\ude74-\ude77\ude79-\ude7c\ude7e\ude80-\ude89\ude8b-\ude9b\udea1-\udea3\udea5-\udea9\udeab-\udebb]|\ud840[\udc00-\udfff]|\ud841[\udc00-\udfff]|\ud842[\udc00-\udfff]|\ud843[\udc00-\udfff]|\ud844[\udc00-\udfff]|\ud845[\udc00-\udfff]|\ud846[\udc00-\udfff]|\ud847[\udc00-\udfff]|\ud848[\udc00-\udfff]|\ud849[\udc00-\udfff]|\ud84a[\udc00-\udfff]|\ud84b[\udc00-\udfff]|\ud84c[\udc00-\udfff]|\ud84d[\udc00-\udfff]|\ud84e[\udc00-\udfff]|\ud84f[\udc00-\udfff]|\ud850[\udc00-\udfff]|\ud851[\udc00-\udfff]|\ud852[\udc00-\udfff]|\ud853[\udc00-\udfff]|\ud854[\udc00-\udfff]|\ud855[\udc00-\udfff]|\ud856[\udc00-\udfff]|\ud857[\udc00-\udfff]|\ud858[\udc00-\udfff]|\ud859[\udc00-\udfff]|\ud85a[\udc00-\udfff]|\ud85b[\udc00-\udfff]|\ud85c[\udc00-\udfff]|\ud85d[\udc00-\udfff]|\ud85e[\udc00-\udfff]|\ud85f[\udc00-\udfff]|\ud860[\udc00-\udfff]|\ud861[\udc00-\udfff]|\ud862[\udc00-\udfff]|\ud863[\udc00-\udfff]|\ud864[\udc00-\udfff]|\ud865[\udc00-\udfff]|\ud866[\udc00-\udfff]|\ud867[\udc00-\udfff]|\ud868[\udc00-\udfff]|\ud869[\udc00-\uded6\udf00-\udfff]|\ud86a[\udc00-\udfff]|\ud86b[\udc00-\udfff]|\ud86c[\udc00-\udfff]|\ud86d[\udc00-\udf34\udf40-\udfff]|\ud86e[\udc00-\udc1d\udc20-\udfff]|\ud86f[\udc00-\udfff]|\ud870[\udc00-\udfff]|\ud871[\udc00-\udfff]|\ud872[\udc00-\udfff]|\ud873[\udc00-\udea1\udeb0-\udfff]|\ud874[\udc00-\udfff]|\ud875[\udc00-\udfff]|\ud876[\udc00-\udfff]|\ud877[\udc00-\udfff]|\ud878[\udc00-\udfff]|\ud879[\udc00-\udfff]|\ud87a[\udc00-\udfe0]|\ud87e[\udc00-\ude1d])|[$_]|(\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,}\}))(([\u0030-\u0039\u0041-\u005a\u005f\u0061-\u007a\u00aa\u00b5\u00b7\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u02c1\u02c6-\u02d1\u02e0-\u02e4\u02ec\u02ee\u0300-\u0374\u0376-\u0377\u037a-\u037d\u037f\u0386-\u038a\u038c\u038e-\u03a1\u03a3-\u03f5\u03f7-\u0481\u0483-\u0487\u048a-\u052f\u0531-\u0556\u0559\u0560-\u0588\u0591-\u05bd\u05bf\u05c1-\u05c2\u05c4-\u05c5\u05c7\u05d0-\u05ea\u05ef-\u05f2\u0610-\u061a\u0620-\u0669\u066e-\u06d3\u06d5-\u06dc\u06df-\u06e8\u06ea-\u06fc\u06ff\u0710-\u074a\u074d-\u07b1\u07c0-\u07f5\u07fa\u07fd\u0800-\u082d\u0840-\u085b\u0860-\u086a\u08a0-\u08b4\u08b6-\u08bd\u08d3-\u08e1\u08e3-\u0963\u0966-\u096f\u0971-\u0983\u0985-\u098c\u098f-\u0990\u0993-\u09a8\u09aa-\u09b0\u09b2\u09b6-\u09b9\u09bc-\u09c4\u09c7-\u09c8\u09cb-\u09ce\u09d7\u09dc-\u09dd\u09df-\u09e3\u09e6-\u09f1\u09fc\u09fe\u0a01-\u0a03\u0a05-\u0a0a\u0a0f-\u0a10\u0a13-\u0a28\u0a2a-\u0a30\u0a32-\u0a33\u0a35-\u0a36\u0a38-\u0a39\u0a3c\u0a3e-\u0a42\u0a47-\u0a48\u0a4b-\u0a4d\u0a51\u0a59-\u0a5c\u0a5e\u0a66-\u0a75\u0a81-\u0a83\u0a85-\u0a8d\u0a8f-\u0a91\u0a93-\u0aa8\u0aaa-\u0ab0\u0ab2-\u0ab3\u0ab5-\u0ab9\u0abc-\u0ac5\u0ac7-\u0ac9\u0acb-\u0acd\u0ad0\u0ae0-\u0ae3\u0ae6-\u0aef\u0af9-\u0aff\u0b01-\u0b03\u0b05-\u0b0c\u0b0f-\u0b10\u0b13-\u0b28\u0b2a-\u0b30\u0b32-\u0b33\u0b35-\u0b39\u0b3c-\u0b44\u0b47-\u0b48\u0b4b-\u0b4d\u0b56-\u0b57\u0b5c-\u0b5d\u0b5f-\u0b63\u0b66-\u0b6f\u0b71\u0b82-\u0b83\u0b85-\u0b8a\u0b8e-\u0b90\u0b92-\u0b95\u0b99-\u0b9a\u0b9c\u0b9e-\u0b9f\u0ba3-\u0ba4\u0ba8-\u0baa\u0bae-\u0bb9\u0bbe-\u0bc2\u0bc6-\u0bc8\u0bca-\u0bcd\u0bd0\u0bd7\u0be6-\u0bef\u0c00-\u0c0c\u0c0e-\u0c10\u0c12-\u0c28\u0c2a-\u0c39\u0c3d-\u0c44\u0c46-\u0c48\u0c4a-\u0c4d\u0c55-\u0c56\u0c58-\u0c5a\u0c60-\u0c63\u0c66-\u0c6f\u0c80-\u0c83\u0c85-\u0c8c\u0c8e-\u0c90\u0c92-\u0ca8\u0caa-\u0cb3\u0cb5-\u0cb9\u0cbc-\u0cc4\u0cc6-\u0cc8\u0cca-\u0ccd\u0cd5-\u0cd6\u0cde\u0ce0-\u0ce3\u0ce6-\u0cef\u0cf1-\u0cf2\u0d00-\u0d03\u0d05-\u0d0c\u0d0e-\u0d10\u0d12-\u0d44\u0d46-\u0d48\u0d4a-\u0d4e\u0d54-\u0d57\u0d5f-\u0d63\u0d66-\u0d6f\u0d7a-\u0d7f\u0d82-\u0d83\u0d85-\u0d96\u0d9a-\u0db1\u0db3-\u0dbb\u0dbd\u0dc0-\u0dc6\u0dca\u0dcf-\u0dd4\u0dd6\u0dd8-\u0ddf\u0de6-\u0def\u0df2-\u0df3\u0e01-\u0e3a\u0e40-\u0e4e\u0e50-\u0e59\u0e81-\u0e82\u0e84\u0e86-\u0e8a\u0e8c-\u0ea3\u0ea5\u0ea7-\u0ebd\u0ec0-\u0ec4\u0ec6\u0ec8-\u0ecd\u0ed0-\u0ed9\u0edc-\u0edf\u0f00\u0f18-\u0f19\u0f20-\u0f29\u0f35\u0f37\u0f39\u0f3e-\u0f47\u0f49-\u0f6c\u0f71-\u0f84\u0f86-\u0f97\u0f99-\u0fbc\u0fc6\u1000-\u1049\u1050-\u109d\u10a0-\u10c5\u10c7\u10cd\u10d0-\u10fa\u10fc-\u1248\u124a-\u124d\u1250-\u1256\u1258\u125a-\u125d\u1260-\u1288\u128a-\u128d\u1290-\u12b0\u12b2-\u12b5\u12b8-\u12be\u12c0\u12c2-\u12c5\u12c8-\u12d6\u12d8-\u1310\u1312-\u1315\u1318-\u135a\u135d-\u135f\u1369-\u1371\u1380-\u138f\u13a0-\u13f5\u13f8-\u13fd\u1401-\u166c\u166f-\u167f\u1681-\u169a\u16a0-\u16ea\u16ee-\u16f8\u1700-\u170c\u170e-\u1714\u1720-\u1734\u1740-\u1753\u1760-\u176c\u176e-\u1770\u1772-\u1773\u1780-\u17d3\u17d7\u17dc-\u17dd\u17e0-\u17e9\u180b-\u180d\u1810-\u1819\u1820-\u1878\u1880-\u18aa\u18b0-\u18f5\u1900-\u191e\u1920-\u192b\u1930-\u193b\u1946-\u196d\u1970-\u1974\u1980-\u19ab\u19b0-\u19c9\u19d0-\u19da\u1a00-\u1a1b\u1a20-\u1a5e\u1a60-\u1a7c\u1a7f-\u1a89\u1a90-\u1a99\u1aa7\u1ab0-\u1abd\u1b00-\u1b4b\u1b50-\u1b59\u1b6b-\u1b73\u1b80-\u1bf3\u1c00-\u1c37\u1c40-\u1c49\u1c4d-\u1c7d\u1c80-\u1c88\u1c90-\u1cba\u1cbd-\u1cbf\u1cd0-\u1cd2\u1cd4-\u1cfa\u1d00-\u1df9\u1dfb-\u1f15\u1f18-\u1f1d\u1f20-\u1f45\u1f48-\u1f4d\u1f50-\u1f57\u1f59\u1f5b\u1f5d\u1f5f-\u1f7d\u1f80-\u1fb4\u1fb6-\u1fbc\u1fbe\u1fc2-\u1fc4\u1fc6-\u1fcc\u1fd0-\u1fd3\u1fd6-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ff4\u1ff6-\u1ffc\u203f-\u2040\u2054\u2071\u207f\u2090-\u209c\u20d0-\u20dc\u20e1\u20e5-\u20f0\u2102\u2107\u210a-\u2113\u2115\u2118-\u211d\u2124\u2126\u2128\u212a-\u2139\u213c-\u213f\u2145-\u2149\u214e\u2160-\u2188\u2c00-\u2c2e\u2c30-\u2c5e\u2c60-\u2ce4\u2ceb-\u2cf3\u2d00-\u2d25\u2d27\u2d2d\u2d30-\u2d67\u2d6f\u2d7f-\u2d96\u2da0-\u2da6\u2da8-\u2dae\u2db0-\u2db6\u2db8-\u2dbe\u2dc0-\u2dc6\u2dc8-\u2dce\u2dd0-\u2dd6\u2dd8-\u2dde\u2de0-\u2dff\u3005-\u3007\u3021-\u302f\u3031-\u3035\u3038-\u303c\u3041-\u3096\u3099-\u309f\u30a1-\u30fa\u30fc-\u30ff\u3105-\u312f\u3131-\u318e\u31a0-\u31ba\u31f0-\u31ff\u3400-\u4db5\u4e00-\u9fef\ua000-\ua48c\ua4d0-\ua4fd\ua500-\ua60c\ua610-\ua62b\ua640-\ua66f\ua674-\ua67d\ua67f-\ua6f1\ua717-\ua71f\ua722-\ua788\ua78b-\ua7bf\ua7c2-\ua7c6\ua7f7-\ua827\ua840-\ua873\ua880-\ua8c5\ua8d0-\ua8d9\ua8e0-\ua8f7\ua8fb\ua8fd-\ua92d\ua930-\ua953\ua960-\ua97c\ua980-\ua9c0\ua9cf-\ua9d9\ua9e0-\ua9fe\uaa00-\uaa36\uaa40-\uaa4d\uaa50-\uaa59\uaa60-\uaa76\uaa7a-\uaac2\uaadb-\uaadd\uaae0-\uaaef\uaaf2-\uaaf6\uab01-\uab06\uab09-\uab0e\uab11-\uab16\uab20-\uab26\uab28-\uab2e\uab30-\uab5a\uab5c-\uab67\uab70-\uabea\uabec-\uabed\uabf0-\uabf9\uac00-\ud7a3\ud7b0-\ud7c6\ud7cb-\ud7fb\uf900-\ufa6d\ufa70-\ufad9\ufb00-\ufb06\ufb13-\ufb17\ufb1d-\ufb28\ufb2a-\ufb36\ufb38-\ufb3c\ufb3e\ufb40-\ufb41\ufb43-\ufb44\ufb46-\ufbb1\ufbd3-\ufd3d\ufd50-\ufd8f\ufd92-\ufdc7\ufdf0-\ufdfb\ufe00-\ufe0f\ufe20-\ufe2f\ufe33-\ufe34\ufe4d-\ufe4f\ufe70-\ufe74\ufe76-\ufefc\uff10-\uff19\uff21-\uff3a\uff3f\uff41-\uff5a\uff66-\uffbe\uffc2-\uffc7\uffca-\uffcf\uffd2-\uffd7\uffda-\uffdc]|\ud800[\udc00-\udc0b\udc0d-\udc26\udc28-\udc3a\udc3c-\udc3d\udc3f-\udc4d\udc50-\udc5d\udc80-\udcfa\udd40-\udd74\uddfd\ude80-\ude9c\udea0-\uded0\udee0\udf00-\udf1f\udf2d-\udf4a\udf50-\udf7a\udf80-\udf9d\udfa0-\udfc3\udfc8-\udfcf\udfd1-\udfd5]|\ud801[\udc00-\udc9d\udca0-\udca9\udcb0-\udcd3\udcd8-\udcfb\udd00-\udd27\udd30-\udd63\ude00-\udf36\udf40-\udf55\udf60-\udf67]|\ud802[\udc00-\udc05\udc08\udc0a-\udc35\udc37-\udc38\udc3c\udc3f-\udc55\udc60-\udc76\udc80-\udc9e\udce0-\udcf2\udcf4-\udcf5\udd00-\udd15\udd20-\udd39\udd80-\uddb7\uddbe-\uddbf\ude00-\ude03\ude05-\ude06\ude0c-\ude13\ude15-\ude17\ude19-\ude35\ude38-\ude3a\ude3f\ude60-\ude7c\ude80-\ude9c\udec0-\udec7\udec9-\udee6\udf00-\udf35\udf40-\udf55\udf60-\udf72\udf80-\udf91]|\ud803[\udc00-\udc48\udc80-\udcb2\udcc0-\udcf2\udd00-\udd27\udd30-\udd39\udf00-\udf1c\udf27\udf30-\udf50\udfe0-\udff6]|\ud804[\udc00-\udc46\udc66-\udc6f\udc7f-\udcba\udcd0-\udce8\udcf0-\udcf9\udd00-\udd34\udd36-\udd3f\udd44-\udd46\udd50-\udd73\udd76\udd80-\uddc4\uddc9-\uddcc\uddd0-\uddda\udddc\ude00-\ude11\ude13-\ude37\ude3e\ude80-\ude86\ude88\ude8a-\ude8d\ude8f-\ude9d\ude9f-\udea8\udeb0-\udeea\udef0-\udef9\udf00-\udf03\udf05-\udf0c\udf0f-\udf10\udf13-\udf28\udf2a-\udf30\udf32-\udf33\udf35-\udf39\udf3b-\udf44\udf47-\udf48\udf4b-\udf4d\udf50\udf57\udf5d-\udf63\udf66-\udf6c\udf70-\udf74]|\ud805[\udc00-\udc4a\udc50-\udc59\udc5e-\udc5f\udc80-\udcc5\udcc7\udcd0-\udcd9\udd80-\uddb5\uddb8-\uddc0\uddd8-\udddd\ude00-\ude40\ude44\ude50-\ude59\ude80-\udeb8\udec0-\udec9\udf00-\udf1a\udf1d-\udf2b\udf30-\udf39]|\ud806[\udc00-\udc3a\udca0-\udce9\udcff\udda0-\udda7\uddaa-\uddd7\uddda-\udde1\udde3-\udde4\ude00-\ude3e\ude47\ude50-\ude99\ude9d\udec0-\udef8]|\ud807[\udc00-\udc08\udc0a-\udc36\udc38-\udc40\udc50-\udc59\udc72-\udc8f\udc92-\udca7\udca9-\udcb6\udd00-\udd06\udd08-\udd09\udd0b-\udd36\udd3a\udd3c-\udd3d\udd3f-\udd47\udd50-\udd59\udd60-\udd65\udd67-\udd68\udd6a-\udd8e\udd90-\udd91\udd93-\udd98\udda0-\udda9\udee0-\udef6]|\ud808[\udc00-\udf99]|\ud809[\udc00-\udc6e\udc80-\udd43]|\ud80c[\udc00-\udfff]|\ud80d[\udc00-\udc2e]|\ud811[\udc00-\ude46]|\ud81a[\udc00-\ude38\ude40-\ude5e\ude60-\ude69\uded0-\udeed\udef0-\udef4\udf00-\udf36\udf40-\udf43\udf50-\udf59\udf63-\udf77\udf7d-\udf8f]|\ud81b[\ude40-\ude7f\udf00-\udf4a\udf4f-\udf87\udf8f-\udf9f\udfe0-\udfe1\udfe3]|\ud81c[\udc00-\udfff]|\ud81d[\udc00-\udfff]|\ud81e[\udc00-\udfff]|\ud81f[\udc00-\udfff]|\ud820[\udc00-\udfff]|\ud821[\udc00-\udff7]|\ud822[\udc00-\udef2]|\ud82c[\udc00-\udd1e\udd50-\udd52\udd64-\udd67\udd70-\udefb]|\ud82f[\udc00-\udc6a\udc70-\udc7c\udc80-\udc88\udc90-\udc99\udc9d-\udc9e]|\ud834[\udd65-\udd69\udd6d-\udd72\udd7b-\udd82\udd85-\udd8b\uddaa-\uddad\ude42-\ude44]|\ud835[\udc00-\udc54\udc56-\udc9c\udc9e-\udc9f\udca2\udca5-\udca6\udca9-\udcac\udcae-\udcb9\udcbb\udcbd-\udcc3\udcc5-\udd05\udd07-\udd0a\udd0d-\udd14\udd16-\udd1c\udd1e-\udd39\udd3b-\udd3e\udd40-\udd44\udd46\udd4a-\udd50\udd52-\udea5\udea8-\udec0\udec2-\udeda\udedc-\udefa\udefc-\udf14\udf16-\udf34\udf36-\udf4e\udf50-\udf6e\udf70-\udf88\udf8a-\udfa8\udfaa-\udfc2\udfc4-\udfcb\udfce-\udfff]|\ud836[\ude00-\ude36\ude3b-\ude6c\ude75\ude84\ude9b-\ude9f\udea1-\udeaf]|\ud838[\udc00-\udc06\udc08-\udc18\udc1b-\udc21\udc23-\udc24\udc26-\udc2a\udd00-\udd2c\udd30-\udd3d\udd40-\udd49\udd4e\udec0-\udef9]|\ud83a[\udc00-\udcc4\udcd0-\udcd6\udd00-\udd4b\udd50-\udd59]|\ud83b[\ude00-\ude03\ude05-\ude1f\ude21-\ude22\ude24\ude27\ude29-\ude32\ude34-\ude37\ude39\ude3b\ude42\ude47\ude49\ude4b\ude4d-\ude4f\ude51-\ude52\ude54\ude57\ude59\ude5b\ude5d\ude5f\ude61-\ude62\ude64\ude67-\ude6a\ude6c-\ude72\ude74-\ude77\ude79-\ude7c\ude7e\ude80-\ude89\ude8b-\ude9b\udea1-\udea3\udea5-\udea9\udeab-\udebb]|\ud840[\udc00-\udfff]|\ud841[\udc00-\udfff]|\ud842[\udc00-\udfff]|\ud843[\udc00-\udfff]|\ud844[\udc00-\udfff]|\ud845[\udc00-\udfff]|\ud846[\udc00-\udfff]|\ud847[\udc00-\udfff]|\ud848[\udc00-\udfff]|\ud849[\udc00-\udfff]|\ud84a[\udc00-\udfff]|\ud84b[\udc00-\udfff]|\ud84c[\udc00-\udfff]|\ud84d[\udc00-\udfff]|\ud84e[\udc00-\udfff]|\ud84f[\udc00-\udfff]|\ud850[\udc00-\udfff]|\ud851[\udc00-\udfff]|\ud852[\udc00-\udfff]|\ud853[\udc00-\udfff]|\ud854[\udc00-\udfff]|\ud855[\udc00-\udfff]|\ud856[\udc00-\udfff]|\ud857[\udc00-\udfff]|\ud858[\udc00-\udfff]|\ud859[\udc00-\udfff]|\ud85a[\udc00-\udfff]|\ud85b[\udc00-\udfff]|\ud85c[\udc00-\udfff]|\ud85d[\udc00-\udfff]|\ud85e[\udc00-\udfff]|\ud85f[\udc00-\udfff]|\ud860[\udc00-\udfff]|\ud861[\udc00-\udfff]|\ud862[\udc00-\udfff]|\ud863[\udc00-\udfff]|\ud864[\udc00-\udfff]|\ud865[\udc00-\udfff]|\ud866[\udc00-\udfff]|\ud867[\udc00-\udfff]|\ud868[\udc00-\udfff]|\ud869[\udc00-\uded6\udf00-\udfff]|\ud86a[\udc00-\udfff]|\ud86b[\udc00-\udfff]|\ud86c[\udc00-\udfff]|\ud86d[\udc00-\udf34\udf40-\udfff]|\ud86e[\udc00-\udc1d\udc20-\udfff]|\ud86f[\udc00-\udfff]|\ud870[\udc00-\udfff]|\ud871[\udc00-\udfff]|\ud872[\udc00-\udfff]|\ud873[\udc00-\udea1\udeb0-\udfff]|\ud874[\udc00-\udfff]|\ud875[\udc00-\udfff]|\ud876[\udc00-\udfff]|\ud877[\udc00-\udfff]|\ud878[\udc00-\udfff]|\ud879[\udc00-\udfff]|\ud87a[\udc00-\udfe0]|\ud87e[\udc00-\ude1d]|\udb40[\udd00-\uddef])|[$_]|(\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,}\})|[\u200c\u200d])*>/, function() {
      yytext = yytext.slice(3, -1);
      validateUnicodeGroupName(yytext, this.getCurrentState());
      return "NAMED_CAPTURE_GROUP";
    }], [/^\(/, function() {
      return "L_PAREN";
    }], [/^\)/, function() {
      return "R_PAREN";
    }], [/^[*?+[^$]/, function() {
      return "CHAR";
    }], [/^\\\]/, function() {
      return "ESC_CHAR";
    }], [/^\]/, function() {
      this.popState();
      return "R_BRACKET";
    }], [/^\^/, function() {
      return "BOS";
    }], [/^\$/, function() {
      return "EOS";
    }], [/^\*/, function() {
      return "STAR";
    }], [/^\?/, function() {
      return "Q_MARK";
    }], [/^\+/, function() {
      return "PLUS";
    }], [/^\|/, function() {
      return "BAR";
    }], [/^\./, function() {
      return "ANY";
    }], [/^\//, function() {
      return "SLASH";
    }], [/^[^*?+\[()\\|]/, function() {
      return "CHAR";
    }], [/^\[\^/, function() {
      var s = this.getCurrentState();
      this.pushState(s === "u" || s === "xu" ? "u_class" : "class");
      return "NEG_CLASS";
    }], [/^\[/, function() {
      var s = this.getCurrentState();
      this.pushState(s === "u" || s === "xu" ? "u_class" : "class");
      return "L_BRACKET";
    }]];
    var lexRulesByConditions = { "INITIAL": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 22, 23, 24, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51], "u": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51], "xu": [0, 1, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51], "x": [0, 1, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 22, 23, 24, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51], "u_class": [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51], "class": [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51] };
    var EOF_TOKEN = {
      type: EOF,
      value: ""
    };
    tokenizer = {
      initString: function initString(string) {
        this._string = string;
        this._cursor = 0;
        this._states = ["INITIAL"];
        this._tokensQueue = [];
        this._currentLine = 1;
        this._currentColumn = 0;
        this._currentLineBeginOffset = 0;
        this._tokenStartOffset = 0;
        this._tokenEndOffset = 0;
        this._tokenStartLine = 1;
        this._tokenEndLine = 1;
        this._tokenStartColumn = 0;
        this._tokenEndColumn = 0;
        return this;
      },
      /**
       * Returns tokenizer states.
       */
      getStates: function getStates() {
        return this._states;
      },
      getCurrentState: function getCurrentState() {
        return this._states[this._states.length - 1];
      },
      pushState: function pushState(state) {
        this._states.push(state);
      },
      begin: function begin(state) {
        this.pushState(state);
      },
      popState: function popState() {
        if (this._states.length > 1) {
          return this._states.pop();
        }
        return this._states[0];
      },
      getNextToken: function getNextToken() {
        if (this._tokensQueue.length > 0) {
          return this.onToken(this._toToken(this._tokensQueue.shift()));
        }
        if (!this.hasMoreTokens()) {
          return this.onToken(EOF_TOKEN);
        }
        var string = this._string.slice(this._cursor);
        var lexRulesForState = lexRulesByConditions[this.getCurrentState()];
        for (var i2 = 0; i2 < lexRulesForState.length; i2++) {
          var lexRuleIndex = lexRulesForState[i2];
          var lexRule = lexRules[lexRuleIndex];
          var matched = this._match(string, lexRule[0]);
          if (string === "" && matched === "") {
            this._cursor++;
          }
          if (matched !== null) {
            yytext = matched;
            yyleng = yytext.length;
            var token = lexRule[1].call(this);
            if (!token) {
              return this.getNextToken();
            }
            if (Array.isArray(token)) {
              var tokensToQueue = token.slice(1);
              token = token[0];
              if (tokensToQueue.length > 0) {
                var _tokensQueue;
                (_tokensQueue = this._tokensQueue).unshift.apply(_tokensQueue, _toConsumableArray(tokensToQueue));
              }
            }
            return this.onToken(this._toToken(token, yytext));
          }
        }
        if (this.isEOF()) {
          this._cursor++;
          return EOF_TOKEN;
        }
        this.throwUnexpectedToken(string[0], this._currentLine, this._currentColumn);
      },
      /**
       * Throws default "Unexpected token" exception, showing the actual
       * line from the source, pointing with the ^ marker to the bad token.
       * In addition, shows `line:column` location.
       */
      throwUnexpectedToken: function throwUnexpectedToken(symbol, line, column) {
        var lineSource = this._string.split("\n")[line - 1];
        var lineData = "";
        if (lineSource) {
          var pad = " ".repeat(column);
          lineData = "\n\n" + lineSource + "\n" + pad + "^\n";
        }
        throw new SyntaxError(lineData + 'Unexpected token: "' + symbol + '" ' + ("at " + line + ":" + column + "."));
      },
      getCursor: function getCursor() {
        return this._cursor;
      },
      getCurrentLine: function getCurrentLine() {
        return this._currentLine;
      },
      getCurrentColumn: function getCurrentColumn() {
        return this._currentColumn;
      },
      _captureLocation: function _captureLocation(matched) {
        var nlRe = /\n/g;
        this._tokenStartOffset = this._cursor;
        this._tokenStartLine = this._currentLine;
        this._tokenStartColumn = this._tokenStartOffset - this._currentLineBeginOffset;
        var nlMatch = void 0;
        while ((nlMatch = nlRe.exec(matched)) !== null) {
          this._currentLine++;
          this._currentLineBeginOffset = this._tokenStartOffset + nlMatch.index + 1;
        }
        this._tokenEndOffset = this._cursor + matched.length;
        this._tokenEndLine = this._currentLine;
        this._tokenEndColumn = this._currentColumn = this._tokenEndOffset - this._currentLineBeginOffset;
      },
      _toToken: function _toToken(tokenType) {
        var yytext2 = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : "";
        return {
          // Basic data.
          type: tokenType,
          value: yytext2,
          // Location data.
          startOffset: this._tokenStartOffset,
          endOffset: this._tokenEndOffset,
          startLine: this._tokenStartLine,
          endLine: this._tokenEndLine,
          startColumn: this._tokenStartColumn,
          endColumn: this._tokenEndColumn
        };
      },
      isEOF: function isEOF() {
        return this._cursor === this._string.length;
      },
      hasMoreTokens: function hasMoreTokens() {
        return this._cursor <= this._string.length;
      },
      _match: function _match(string, regexp) {
        var matched = string.match(regexp);
        if (matched) {
          this._captureLocation(matched[0]);
          this._cursor += matched[0].length;
          return matched[0];
        }
        return null;
      },
      /**
       * Allows analyzing, and transforming token. Default implementation
       * just passes the token through.
       */
      onToken: function onToken(token) {
        return token;
      }
    };
    yy.lexer = tokenizer;
    yy.tokenizer = tokenizer;
    yy.options = {
      captureLocations: true
    };
    var yyparse = {
      /**
       * Sets global parsing options.
       */
      setOptions: function setOptions(options) {
        yy.options = options;
        return this;
      },
      /**
       * Returns parsing options.
       */
      getOptions: function getOptions() {
        return yy.options;
      },
      /**
       * Parses a string.
       */
      parse: function parse(string, parseOptions) {
        if (!tokenizer) {
          throw new Error("Tokenizer instance wasn't specified.");
        }
        tokenizer.initString(string);
        var globalOptions = yy.options;
        if (parseOptions) {
          yy.options = Object.assign({}, yy.options, parseOptions);
        }
        yyparse.onParseBegin(string, tokenizer, yy.options);
        stack.length = 0;
        stack.push(0);
        var token = tokenizer.getNextToken();
        var shiftedToken = null;
        do {
          if (!token) {
            yy.options = globalOptions;
            unexpectedEndOfInput();
          }
          var state = stack[stack.length - 1];
          var column = tokens[token.type];
          if (!table[state].hasOwnProperty(column)) {
            yy.options = globalOptions;
            unexpectedToken(token);
          }
          var entry = table[state][column];
          if (entry[0] === "s") {
            var _loc2 = null;
            if (yy.options.captureLocations) {
              _loc2 = {
                startOffset: token.startOffset,
                endOffset: token.endOffset,
                startLine: token.startLine,
                endLine: token.endLine,
                startColumn: token.startColumn,
                endColumn: token.endColumn
              };
            }
            shiftedToken = this.onShift(token);
            stack.push({ symbol: tokens[shiftedToken.type], semanticValue: shiftedToken.value, loc: _loc2 }, Number(entry.slice(1)));
            token = tokenizer.getNextToken();
          } else if (entry[0] === "r") {
            var productionNumber = entry.slice(1);
            var production = productions[productionNumber];
            var hasSemanticAction = typeof production[2] === "function";
            var semanticValueArgs = hasSemanticAction ? [] : null;
            var locationArgs = hasSemanticAction && yy.options.captureLocations ? [] : null;
            if (production[1] !== 0) {
              var rhsLength = production[1];
              while (rhsLength-- > 0) {
                stack.pop();
                var stackEntry = stack.pop();
                if (hasSemanticAction) {
                  semanticValueArgs.unshift(stackEntry.semanticValue);
                  if (locationArgs) {
                    locationArgs.unshift(stackEntry.loc);
                  }
                }
              }
            }
            var reduceStackEntry = { symbol: production[0] };
            if (hasSemanticAction) {
              yytext = shiftedToken ? shiftedToken.value : null;
              yyleng = shiftedToken ? shiftedToken.value.length : null;
              var semanticActionArgs = locationArgs !== null ? semanticValueArgs.concat(locationArgs) : semanticValueArgs;
              production[2].apply(production, _toConsumableArray(semanticActionArgs));
              reduceStackEntry.semanticValue = __;
              if (locationArgs) {
                reduceStackEntry.loc = __loc;
              }
            }
            var nextState = stack[stack.length - 1];
            var symbolToReduceWith = production[0];
            stack.push(reduceStackEntry, table[nextState][symbolToReduceWith]);
          } else if (entry === "acc") {
            stack.pop();
            var parsed = stack.pop();
            if (stack.length !== 1 || stack[0] !== 0 || tokenizer.hasMoreTokens()) {
              yy.options = globalOptions;
              unexpectedToken(token);
            }
            if (parsed.hasOwnProperty("semanticValue")) {
              yy.options = globalOptions;
              yyparse.onParseEnd(parsed.semanticValue);
              return parsed.semanticValue;
            }
            yyparse.onParseEnd();
            yy.options = globalOptions;
            return true;
          }
        } while (tokenizer.hasMoreTokens() || stack.length > 1);
      },
      setTokenizer: function setTokenizer(customTokenizer) {
        tokenizer = customTokenizer;
        return yyparse;
      },
      getTokenizer: function getTokenizer() {
        return tokenizer;
      },
      onParseBegin: function onParseBegin(string, tokenizer2, options) {
      },
      onParseEnd: function onParseEnd(parsed) {
      },
      /**
       * Allows analyzing, and transforming shifted token. Default implementation
       * just passes the token through.
       */
      onShift: function onShift(token) {
        return token;
      }
    };
    var capturingGroupsCount = 0;
    var namedGroups = {};
    var parsingString = "";
    yyparse.onParseBegin = function(string, lexer) {
      parsingString = string;
      capturingGroupsCount = 0;
      namedGroups = {};
      var lastSlash = string.lastIndexOf("/");
      var flags = string.slice(lastSlash);
      if (flags.includes("x") && flags.includes("u")) {
        lexer.pushState("xu");
      } else {
        if (flags.includes("x")) {
          lexer.pushState("x");
        }
        if (flags.includes("u")) {
          lexer.pushState("u");
        }
      }
    };
    yyparse.onShift = function(token) {
      if (token.type === "L_PAREN" || token.type === "NAMED_CAPTURE_GROUP") {
        token.value = new String(token.value);
        token.value.groupNumber = ++capturingGroupsCount;
      }
      return token;
    };
    function getRange(text) {
      var range = text.match(/\d+/g).map(Number);
      if (Number.isFinite(range[1]) && range[1] < range[0]) {
        throw new SyntaxError("Numbers out of order in " + text + " quantifier");
      }
      return range;
    }
    function checkClassRange(from, to) {
      if (from.kind === "control" || to.kind === "control" || !isNaN(from.codePoint) && !isNaN(to.codePoint) && from.codePoint > to.codePoint) {
        throw new SyntaxError("Range " + from.value + "-" + to.value + " out of order in character class");
      }
    }
    var unicodeProperties = require_parser_unicode_properties();
    function UnicodeProperty(matched, loc2) {
      var negative = matched[1] === "P";
      var separatorIdx = matched.indexOf("=");
      var name = matched.slice(3, separatorIdx !== -1 ? separatorIdx : -1);
      var value = void 0;
      var isShorthand = separatorIdx === -1 && unicodeProperties.isGeneralCategoryValue(name);
      var isBinaryProperty = separatorIdx === -1 && unicodeProperties.isBinaryPropertyName(name);
      if (isShorthand) {
        value = name;
        name = "General_Category";
      } else if (isBinaryProperty) {
        value = name;
      } else {
        if (!unicodeProperties.isValidName(name)) {
          throw new SyntaxError("Invalid unicode property name: " + name + ".");
        }
        value = matched.slice(separatorIdx + 1, -1);
        if (!unicodeProperties.isValidValue(name, value)) {
          throw new SyntaxError("Invalid " + name + " unicode property value: " + value + ".");
        }
      }
      return Node({
        type: "UnicodeProperty",
        name,
        value,
        negative,
        shorthand: isShorthand,
        binary: isBinaryProperty,
        canonicalName: unicodeProperties.getCanonicalName(name) || name,
        canonicalValue: unicodeProperties.getCanonicalValue(value) || value
      }, loc2);
    }
    function Char(value, kind, loc2) {
      var symbol = void 0;
      var codePoint = void 0;
      switch (kind) {
        case "decimal": {
          codePoint = Number(value.slice(1));
          symbol = String.fromCodePoint(codePoint);
          break;
        }
        case "oct": {
          codePoint = parseInt(value.slice(1), 8);
          symbol = String.fromCodePoint(codePoint);
          break;
        }
        case "hex":
        case "unicode": {
          if (value.lastIndexOf("\\u") > 0) {
            var _value$split$slice = value.split("\\u").slice(1), _value$split$slice2 = _slicedToArray(_value$split$slice, 2), lead = _value$split$slice2[0], trail = _value$split$slice2[1];
            lead = parseInt(lead, 16);
            trail = parseInt(trail, 16);
            codePoint = (lead - 55296) * 1024 + (trail - 56320) + 65536;
            symbol = String.fromCodePoint(codePoint);
          } else {
            var hex = value.slice(2).replace("{", "");
            codePoint = parseInt(hex, 16);
            if (codePoint > 1114111) {
              throw new SyntaxError("Bad character escape sequence: " + value);
            }
            symbol = String.fromCodePoint(codePoint);
          }
          break;
        }
        case "meta": {
          switch (value) {
            case "\\t":
              symbol = "	";
              codePoint = symbol.codePointAt(0);
              break;
            case "\\n":
              symbol = "\n";
              codePoint = symbol.codePointAt(0);
              break;
            case "\\r":
              symbol = "\r";
              codePoint = symbol.codePointAt(0);
              break;
            case "\\v":
              symbol = "\v";
              codePoint = symbol.codePointAt(0);
              break;
            case "\\f":
              symbol = "\f";
              codePoint = symbol.codePointAt(0);
              break;
            case "\\b":
              symbol = "\b";
              codePoint = symbol.codePointAt(0);
            case "\\0":
              symbol = "\0";
              codePoint = 0;
            case ".":
              symbol = ".";
              codePoint = NaN;
              break;
            default:
              codePoint = NaN;
          }
          break;
        }
        case "simple": {
          symbol = value;
          codePoint = symbol.codePointAt(0);
          break;
        }
      }
      return Node({
        type: "Char",
        value,
        kind,
        symbol,
        codePoint
      }, loc2);
    }
    var validFlags = "gimsuxy";
    function checkFlags(flags) {
      var seen = /* @__PURE__ */ new Set();
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = void 0;
      try {
        for (var _iterator = flags[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var flag = _step.value;
          if (seen.has(flag) || !validFlags.includes(flag)) {
            throw new SyntaxError("Invalid flags: " + flags);
          }
          seen.add(flag);
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator.return) {
            _iterator.return();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
      return flags.split("").sort().join("");
    }
    function GroupRefOrDecChar(text, textLoc) {
      var reference2 = Number(text.slice(1));
      if (reference2 > 0 && reference2 <= capturingGroupsCount) {
        return Node({
          type: "Backreference",
          kind: "number",
          number: reference2,
          reference: reference2
        }, textLoc);
      }
      return Char(text, "decimal", textLoc);
    }
    var uReStart = /^\\u[0-9a-fA-F]{4}/;
    var ucpReStart = /^\\u\{[0-9a-fA-F]{1,}\}/;
    var ucpReAnywhere = /\\u\{[0-9a-fA-F]{1,}\}/;
    function validateUnicodeGroupName(name, state) {
      var isUnicodeName = ucpReAnywhere.test(name);
      var isUnicodeState = state === "u" || state === "xu" || state === "u_class";
      if (isUnicodeName && !isUnicodeState) {
        throw new SyntaxError('invalid group Unicode name "' + name + '", use `u` flag.');
      }
      return name;
    }
    var uidRe = /\\u(?:([dD][89aAbB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})|([dD][89aAbB][0-9a-fA-F]{2})|([dD][c-fC-F][0-9a-fA-F]{2})|([0-9a-ce-fA-CE-F][0-9a-fA-F]{3}|[dD][0-7][0-9a-fA-F]{2})|\{(0*(?:[0-9a-fA-F]{1,5}|10[0-9a-fA-F]{4}))\})/;
    function decodeUnicodeGroupName(name) {
      return name.replace(new RegExp(uidRe, "g"), function(_, leadSurrogate, trailSurrogate, leadSurrogateOnly, trailSurrogateOnly, nonSurrogate, codePoint) {
        if (leadSurrogate) {
          return String.fromCodePoint(parseInt(leadSurrogate, 16), parseInt(trailSurrogate, 16));
        }
        if (leadSurrogateOnly) {
          return String.fromCodePoint(parseInt(leadSurrogateOnly, 16));
        }
        if (trailSurrogateOnly) {
          return String.fromCodePoint(parseInt(trailSurrogateOnly, 16));
        }
        if (nonSurrogate) {
          return String.fromCodePoint(parseInt(nonSurrogate, 16));
        }
        if (codePoint) {
          return String.fromCodePoint(parseInt(codePoint, 16));
        }
        return _;
      });
    }
    function NamedGroupRefOrChars(text, textLoc) {
      var referenceRaw = text.slice(3, -1);
      var reference2 = decodeUnicodeGroupName(referenceRaw);
      if (namedGroups.hasOwnProperty(reference2)) {
        return Node({
          type: "Backreference",
          kind: "name",
          number: namedGroups[reference2],
          reference: reference2,
          referenceRaw
        }, textLoc);
      }
      var startOffset = null;
      var startLine = null;
      var endLine = null;
      var startColumn = null;
      if (textLoc) {
        startOffset = textLoc.startOffset;
        startLine = textLoc.startLine;
        endLine = textLoc.endLine;
        startColumn = textLoc.startColumn;
      }
      var charRe = /^[\w$<>]/;
      var loc2 = void 0;
      var chars = [
        // Init to first \k, taking 2 symbols.
        Char(text.slice(1, 2), "simple", startOffset ? {
          startLine,
          endLine,
          startColumn,
          startOffset,
          endOffset: startOffset += 2,
          endColumn: startColumn += 2
        } : null)
      ];
      chars[0].escaped = true;
      text = text.slice(2);
      while (text.length > 0) {
        var matched = null;
        if ((matched = text.match(uReStart)) || (matched = text.match(ucpReStart))) {
          if (startOffset) {
            loc2 = {
              startLine,
              endLine,
              startColumn,
              startOffset,
              endOffset: startOffset += matched[0].length,
              endColumn: startColumn += matched[0].length
            };
          }
          chars.push(Char(matched[0], "unicode", loc2));
          text = text.slice(matched[0].length);
        } else if (matched = text.match(charRe)) {
          if (startOffset) {
            loc2 = {
              startLine,
              endLine,
              startColumn,
              startOffset,
              endOffset: ++startOffset,
              endColumn: ++startColumn
            };
          }
          chars.push(Char(matched[0], "simple", loc2));
          text = text.slice(1);
        }
      }
      return chars;
    }
    function Node(node, loc2) {
      if (yy.options.captureLocations) {
        node.loc = {
          source: parsingString.slice(loc2.startOffset, loc2.endOffset),
          start: {
            line: loc2.startLine,
            column: loc2.startColumn,
            offset: loc2.startOffset
          },
          end: {
            line: loc2.endLine,
            column: loc2.endColumn,
            offset: loc2.endOffset
          }
        };
      }
      return node;
    }
    function loc(start, end) {
      if (!yy.options.captureLocations) {
        return null;
      }
      return {
        startOffset: start.startOffset,
        endOffset: end.endOffset,
        startLine: start.startLine,
        endLine: end.endLine,
        startColumn: start.startColumn,
        endColumn: end.endColumn
      };
    }
    function unexpectedToken(token) {
      if (token.type === EOF) {
        unexpectedEndOfInput();
      }
      tokenizer.throwUnexpectedToken(token.value, token.startLine, token.startColumn);
    }
    function unexpectedEndOfInput() {
      parseError("Unexpected end of input.");
    }
    function parseError(message) {
      throw new SyntaxError(message);
    }
    module.exports = yyparse;
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/parser/index.js
var require_parser = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/parser/index.js"(exports, module) {
    "use strict";
    var regexpTreeParser = require_regexp_tree();
    var generatedParseFn = regexpTreeParser.parse.bind(regexpTreeParser);
    regexpTreeParser.parse = function(regexp, options) {
      return generatedParseFn("" + regexp, options);
    };
    regexpTreeParser.setOptions({ captureLocations: false });
    module.exports = regexpTreeParser;
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/traverse/node-path.js
var require_node_path = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/traverse/node-path.js"(exports, module) {
    "use strict";
    var _createClass = /* @__PURE__ */ (function() {
      function defineProperties(target, props) {
        for (var i2 = 0; i2 < props.length; i2++) {
          var descriptor = props[i2];
          descriptor.enumerable = descriptor.enumerable || false;
          descriptor.configurable = true;
          if ("value" in descriptor) descriptor.writable = true;
          Object.defineProperty(target, descriptor.key, descriptor);
        }
      }
      return function(Constructor, protoProps, staticProps) {
        if (protoProps) defineProperties(Constructor.prototype, protoProps);
        if (staticProps) defineProperties(Constructor, staticProps);
        return Constructor;
      };
    })();
    function _classCallCheck(instance, Constructor) {
      if (!(instance instanceof Constructor)) {
        throw new TypeError("Cannot call a class as a function");
      }
    }
    var DEFAULT_COLLECTION_PROP = "expressions";
    var DEFAULT_SINGLE_PROP = "expression";
    var NodePath = (function() {
      function NodePath2(node) {
        var parentPath = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : null;
        var property = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : null;
        var index = arguments.length > 3 && arguments[3] !== void 0 ? arguments[3] : null;
        _classCallCheck(this, NodePath2);
        this.node = node;
        this.parentPath = parentPath;
        this.parent = parentPath ? parentPath.node : null;
        this.property = property;
        this.index = index;
      }
      _createClass(NodePath2, [{
        key: "_enforceProp",
        value: function _enforceProp(property) {
          if (!this.node.hasOwnProperty(property)) {
            throw new Error("Node of type " + this.node.type + ` doesn't have "` + property + '" collection.');
          }
        }
        /**
         * Sets a node into a children collection or the single child.
         * By default child nodes are supposed to be under `expressions` property.
         * An explicit property can be passed.
         *
         * @param Object node - a node to set into a collection or as single child
         * @param number index - index at which to set
         * @param string property - name of the collection or single property
         */
      }, {
        key: "setChild",
        value: function setChild(node) {
          var index = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : null;
          var property = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : null;
          var childPath = void 0;
          if (index != null) {
            if (!property) {
              property = DEFAULT_COLLECTION_PROP;
            }
            this._enforceProp(property);
            this.node[property][index] = node;
            childPath = NodePath2.getForNode(node, this, property, index);
          } else {
            if (!property) {
              property = DEFAULT_SINGLE_PROP;
            }
            this._enforceProp(property);
            this.node[property] = node;
            childPath = NodePath2.getForNode(node, this, property, null);
          }
          return childPath;
        }
        /**
         * Appends a node to a children collection.
         * By default child nodes are supposed to be under `expressions` property.
         * An explicit property can be passed.
         *
         * @param Object node - a node to set into a collection or as single child
         * @param string property - name of the collection or single property
         */
      }, {
        key: "appendChild",
        value: function appendChild(node) {
          var property = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : null;
          if (!property) {
            property = DEFAULT_COLLECTION_PROP;
          }
          this._enforceProp(property);
          var end = this.node[property].length;
          return this.setChild(node, end, property);
        }
        /**
         * Inserts a node into a collection.
         * By default child nodes are supposed to be under `expressions` property.
         * An explicit property can be passed.
         *
         * @param Object node - a node to insert into a collection
         * @param number index - index at which to insert
         * @param string property - name of the collection property
         */
      }, {
        key: "insertChildAt",
        value: function insertChildAt(node, index) {
          var property = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : DEFAULT_COLLECTION_PROP;
          this._enforceProp(property);
          this.node[property].splice(index, 0, node);
          if (index <= NodePath2.getTraversingIndex()) {
            NodePath2.updateTraversingIndex(1);
          }
          this._rebuildIndex(this.node, property);
        }
        /**
         * Removes a node.
         */
      }, {
        key: "remove",
        value: function remove() {
          if (this.isRemoved()) {
            return;
          }
          NodePath2.registry.delete(this.node);
          this.node = null;
          if (!this.parent) {
            return;
          }
          if (this.index !== null) {
            this.parent[this.property].splice(this.index, 1);
            if (this.index <= NodePath2.getTraversingIndex()) {
              NodePath2.updateTraversingIndex(-1);
            }
            this._rebuildIndex(this.parent, this.property);
            this.index = null;
            this.property = null;
            return;
          }
          delete this.parent[this.property];
          this.property = null;
        }
        /**
         * Rebuilds child nodes index (used on remove/insert).
         */
      }, {
        key: "_rebuildIndex",
        value: function _rebuildIndex(parent, property) {
          var parentPath = NodePath2.getForNode(parent);
          for (var i2 = 0; i2 < parent[property].length; i2++) {
            var path = NodePath2.getForNode(parent[property][i2], parentPath, property, i2);
            path.index = i2;
          }
        }
        /**
         * Whether the path was removed.
         */
      }, {
        key: "isRemoved",
        value: function isRemoved() {
          return this.node === null;
        }
        /**
         * Replaces a node with the passed one.
         */
      }, {
        key: "replace",
        value: function replace(newNode) {
          NodePath2.registry.delete(this.node);
          this.node = newNode;
          if (!this.parent) {
            return null;
          }
          if (this.index !== null) {
            this.parent[this.property][this.index] = newNode;
          } else {
            this.parent[this.property] = newNode;
          }
          return NodePath2.getForNode(newNode, this.parentPath, this.property, this.index);
        }
        /**
         * Updates a node inline.
         */
      }, {
        key: "update",
        value: function update(nodeProps) {
          Object.assign(this.node, nodeProps);
        }
        /**
         * Returns parent.
         */
      }, {
        key: "getParent",
        value: function getParent() {
          return this.parentPath;
        }
        /**
         * Returns nth child.
         */
      }, {
        key: "getChild",
        value: function getChild() {
          var n = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : 0;
          if (this.node.expressions) {
            return NodePath2.getForNode(this.node.expressions[n], this, DEFAULT_COLLECTION_PROP, n);
          } else if (this.node.expression && n == 0) {
            return NodePath2.getForNode(this.node.expression, this, DEFAULT_SINGLE_PROP);
          }
          return null;
        }
        /**
         * Whether a path node is syntactically equal to the passed one.
         *
         * NOTE: we don't rely on `source` property from the `loc` data
         * (which would be the fastest comparison), since it might be unsync
         * after several modifications. We use here simple `JSON.stringify`
         * excluding the `loc` data.
         *
         * @param NodePath other - path to compare to.
         * @return boolean
         */
      }, {
        key: "hasEqualSource",
        value: function hasEqualSource(path) {
          return JSON.stringify(this.node, jsonSkipLoc) === JSON.stringify(path.node, jsonSkipLoc);
        }
        /**
         * JSON-encodes a node skipping location.
         */
      }, {
        key: "jsonEncode",
        value: function jsonEncode() {
          var _ref = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : {}, format = _ref.format, useLoc = _ref.useLoc;
          return JSON.stringify(this.node, useLoc ? null : jsonSkipLoc, format);
        }
        /**
         * Returns previous sibling.
         */
      }, {
        key: "getPreviousSibling",
        value: function getPreviousSibling() {
          if (!this.parent || this.index == null) {
            return null;
          }
          return NodePath2.getForNode(this.parent[this.property][this.index - 1], NodePath2.getForNode(this.parent), this.property, this.index - 1);
        }
        /**
         * Returns next sibling.
         */
      }, {
        key: "getNextSibling",
        value: function getNextSibling() {
          if (!this.parent || this.index == null) {
            return null;
          }
          return NodePath2.getForNode(this.parent[this.property][this.index + 1], NodePath2.getForNode(this.parent), this.property, this.index + 1);
        }
        /**
         * Returns a NodePath instance for a node.
         *
         * The same NodePath can be reused in several places, e.g.
         * a parent node passed for all its children.
         */
      }], [{
        key: "getForNode",
        value: function getForNode(node) {
          var parentPath = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : null;
          var prop = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : null;
          var index = arguments.length > 3 && arguments[3] !== void 0 ? arguments[3] : -1;
          if (!node) {
            return null;
          }
          if (!NodePath2.registry.has(node)) {
            NodePath2.registry.set(node, new NodePath2(node, parentPath, prop, index == -1 ? null : index));
          }
          var path = NodePath2.registry.get(node);
          if (parentPath !== null) {
            path.parentPath = parentPath;
            path.parent = path.parentPath.node;
          }
          if (prop !== null) {
            path.property = prop;
          }
          if (index >= 0) {
            path.index = index;
          }
          return path;
        }
        /**
         * Initializes the NodePath registry. The registry is a map from
         * a node to its NodePath instance.
         */
      }, {
        key: "initRegistry",
        value: function initRegistry() {
          if (!NodePath2.registry) {
            NodePath2.registry = /* @__PURE__ */ new Map();
          }
          NodePath2.registry.clear();
        }
        /**
         * Updates index of a currently traversing collection.
         */
      }, {
        key: "updateTraversingIndex",
        value: function updateTraversingIndex(dx) {
          return NodePath2.traversingIndexStack[NodePath2.traversingIndexStack.length - 1] += dx;
        }
        /**
         * Returns current traversing index.
         */
      }, {
        key: "getTraversingIndex",
        value: function getTraversingIndex() {
          return NodePath2.traversingIndexStack[NodePath2.traversingIndexStack.length - 1];
        }
      }]);
      return NodePath2;
    })();
    NodePath.initRegistry();
    NodePath.traversingIndexStack = [];
    function jsonSkipLoc(prop, value) {
      if (prop === "loc") {
        return void 0;
      }
      return value;
    }
    module.exports = NodePath;
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/traverse/index.js
var require_traverse = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/traverse/index.js"(exports, module) {
    "use strict";
    var NodePath = require_node_path();
    function astTraverse(root) {
      var options = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {};
      var pre = options.pre;
      var post = options.post;
      var skipProperty = options.skipProperty;
      function visit(node, parent, prop, idx) {
        if (!node || typeof node.type !== "string") {
          return;
        }
        var res = void 0;
        if (pre) {
          res = pre(node, parent, prop, idx);
        }
        if (res !== false) {
          if (parent && parent[prop]) {
            if (!isNaN(idx)) {
              node = parent[prop][idx];
            } else {
              node = parent[prop];
            }
          }
          for (var _prop in node) {
            if (node.hasOwnProperty(_prop)) {
              if (skipProperty ? skipProperty(_prop, node) : _prop[0] === "$") {
                continue;
              }
              var child = node[_prop];
              if (Array.isArray(child)) {
                var index = 0;
                NodePath.traversingIndexStack.push(index);
                while (index < child.length) {
                  visit(child[index], node, _prop, index);
                  index = NodePath.updateTraversingIndex(1);
                }
                NodePath.traversingIndexStack.pop();
              } else {
                visit(child, node, _prop);
              }
            }
          }
        }
        if (post) {
          post(node, parent, prop, idx);
        }
      }
      visit(root, null);
    }
    module.exports = {
      /**
       * Traverses an AST.
       *
       * @param Object ast - an AST node
       *
       * @param Object | Array<Object> handlers:
       *
       *   an object (or an array of objects)
       *
       *   Each such object contains a handler function per node.
       *   In case of an array of handlers, they are applied in order.
       *   A handler may return a transformed node (or a different type).
       *
       *   The per-node function may instead be an object with functions pre and post.
       *   pre is called before visiting the node, post after.
       *   If a handler is a function, it is treated as the pre function, with an empty post.
       *
       * @param Object options:
       *
       *   a config object, specifying traversal options:
       *
       *   `asNodes`: boolean - whether handlers should receives raw AST nodes
       *   (false by default), instead of a `NodePath` wrapper. Note, by default
       *   `NodePath` wrapper provides a set of convenient method to manipulate
       *   a traversing AST, and also has access to all parents list. A raw
       *   nodes traversal should be used in rare cases, when no `NodePath`
       *   features are needed.
       *
       * Special hooks:
       *
       *   - `shouldRun(ast)` - a predicate determining whether the handler
       *                        should be applied.
       *
       * NOTE: Multiple handlers are used as an optimization of applying all of
       * them in one AST traversal pass.
       */
      traverse: function traverse(ast, handlers) {
        var options = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : { asNodes: false };
        if (!Array.isArray(handlers)) {
          handlers = [handlers];
        }
        handlers = handlers.filter(function(handler) {
          if (typeof handler.shouldRun !== "function") {
            return true;
          }
          return handler.shouldRun(ast);
        });
        NodePath.initRegistry();
        handlers.forEach(function(handler) {
          if (typeof handler.init === "function") {
            handler.init(ast);
          }
        });
        function getPathFor(node, parent, prop, index) {
          var parentPath = NodePath.getForNode(parent);
          var nodePath = NodePath.getForNode(node, parentPath, prop, index);
          return nodePath;
        }
        astTraverse(ast, {
          /**
           * Handler on node enter.
           */
          pre: function pre(node, parent, prop, index) {
            var nodePath = void 0;
            if (!options.asNodes) {
              nodePath = getPathFor(node, parent, prop, index);
            }
            var _iteratorNormalCompletion = true;
            var _didIteratorError = false;
            var _iteratorError = void 0;
            try {
              for (var _iterator = handlers[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
                var handler = _step.value;
                if (typeof handler["*"] === "function") {
                  if (nodePath) {
                    if (!nodePath.isRemoved()) {
                      var handlerResult = handler["*"](nodePath);
                      if (handlerResult === false) {
                        return false;
                      }
                    }
                  } else {
                    handler["*"](node, parent, prop, index);
                  }
                }
                var handlerFuncPre = void 0;
                if (typeof handler[node.type] === "function") {
                  handlerFuncPre = handler[node.type];
                } else if (typeof handler[node.type] === "object" && typeof handler[node.type].pre === "function") {
                  handlerFuncPre = handler[node.type].pre;
                }
                if (handlerFuncPre) {
                  if (nodePath) {
                    if (!nodePath.isRemoved()) {
                      var _handlerResult = handlerFuncPre.call(handler, nodePath);
                      if (_handlerResult === false) {
                        return false;
                      }
                    }
                  } else {
                    handlerFuncPre.call(handler, node, parent, prop, index);
                  }
                }
              }
            } catch (err) {
              _didIteratorError = true;
              _iteratorError = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion && _iterator.return) {
                  _iterator.return();
                }
              } finally {
                if (_didIteratorError) {
                  throw _iteratorError;
                }
              }
            }
          },
          // pre func
          /**
           * Handler on node exit.
           */
          post: function post(node, parent, prop, index) {
            if (!node) {
              return;
            }
            var nodePath = void 0;
            if (!options.asNodes) {
              nodePath = getPathFor(node, parent, prop, index);
            }
            var _iteratorNormalCompletion2 = true;
            var _didIteratorError2 = false;
            var _iteratorError2 = void 0;
            try {
              for (var _iterator2 = handlers[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
                var handler = _step2.value;
                var handlerFuncPost = void 0;
                if (typeof handler[node.type] === "object" && typeof handler[node.type].post === "function") {
                  handlerFuncPost = handler[node.type].post;
                }
                if (handlerFuncPost) {
                  if (nodePath) {
                    if (!nodePath.isRemoved()) {
                      var handlerResult = handlerFuncPost.call(handler, nodePath);
                      if (handlerResult === false) {
                        return false;
                      }
                    }
                  } else {
                    handlerFuncPost.call(handler, node, parent, prop, index);
                  }
                }
              }
            } catch (err) {
              _didIteratorError2 = true;
              _iteratorError2 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion2 && _iterator2.return) {
                  _iterator2.return();
                }
              } finally {
                if (_didIteratorError2) {
                  throw _iteratorError2;
                }
              }
            }
          },
          // post func
          /**
           * Skip locations by default.
           */
          skipProperty: function skipProperty(prop) {
            return prop === "loc";
          }
        });
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/transform/index.js
var require_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/transform/index.js"(exports, module) {
    "use strict";
    var _createClass = /* @__PURE__ */ (function() {
      function defineProperties(target, props) {
        for (var i2 = 0; i2 < props.length; i2++) {
          var descriptor = props[i2];
          descriptor.enumerable = descriptor.enumerable || false;
          descriptor.configurable = true;
          if ("value" in descriptor) descriptor.writable = true;
          Object.defineProperty(target, descriptor.key, descriptor);
        }
      }
      return function(Constructor, protoProps, staticProps) {
        if (protoProps) defineProperties(Constructor.prototype, protoProps);
        if (staticProps) defineProperties(Constructor, staticProps);
        return Constructor;
      };
    })();
    function _classCallCheck(instance, Constructor) {
      if (!(instance instanceof Constructor)) {
        throw new TypeError("Cannot call a class as a function");
      }
    }
    var generator = require_generator();
    var parser = require_parser();
    var traverse = require_traverse();
    var TransformResult = (function() {
      function TransformResult2(ast) {
        var extra = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : null;
        _classCallCheck(this, TransformResult2);
        this._ast = ast;
        this._source = null;
        this._string = null;
        this._regexp = null;
        this._extra = extra;
      }
      _createClass(TransformResult2, [{
        key: "getAST",
        value: function getAST() {
          return this._ast;
        }
      }, {
        key: "setExtra",
        value: function setExtra(extra) {
          this._extra = extra;
        }
      }, {
        key: "getExtra",
        value: function getExtra() {
          return this._extra;
        }
      }, {
        key: "toRegExp",
        value: function toRegExp() {
          if (!this._regexp) {
            this._regexp = new RegExp(this.getSource(), this._ast.flags);
          }
          return this._regexp;
        }
      }, {
        key: "getSource",
        value: function getSource() {
          if (!this._source) {
            this._source = generator.generate(this._ast.body);
          }
          return this._source;
        }
      }, {
        key: "getFlags",
        value: function getFlags() {
          return this._ast.flags;
        }
      }, {
        key: "toString",
        value: function toString2() {
          if (!this._string) {
            this._string = generator.generate(this._ast);
          }
          return this._string;
        }
      }]);
      return TransformResult2;
    })();
    module.exports = {
      /**
       * Expose `TransformResult`.
       */
      TransformResult,
      /**
       * Transforms a regular expression applying a set of
       * transformation handlers.
       *
       * @param string | AST | RegExp:
       *
       *   a regular expression in different representations: a string,
       *   a RegExp object, or an AST.
       *
       * @param Object | Array<Object>:
       *
       *   a handler (or a list of handlers) from `traverse` API.
       *
       * @return TransformResult instance.
       *
       * Example:
       *
       *   transform(/[a-z]/i, {
       *     onChar(path) {
       *       const {node} = path;
       *
       *       if (...) {
       *         path.remove();
       *       }
       *     }
       *   });
       */
      transform: function transform(regexp, handlers) {
        var ast = regexp;
        if (regexp instanceof RegExp) {
          regexp = "" + regexp;
        }
        if (typeof regexp === "string") {
          ast = parser.parse(regexp, {
            captureLocations: true
          });
        }
        traverse.traverse(ast, handlers);
        return new TransformResult(ast);
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/index.js
var require_compat_transpiler = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/index.js"(exports, module) {
    "use strict";
    var compatTransforms = require_transforms();
    var _transform = require_transform();
    module.exports = {
      /**
       * Translates a regexp in new syntax to equivalent regexp in old syntax.
       *
       * @param string|RegExp|AST - regexp
       * @param Array transformsWhitelist - names of the transforms to apply
       */
      transform: function transform(regexp) {
        var transformsWhitelist = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : [];
        var transformToApply = transformsWhitelist.length > 0 ? transformsWhitelist : Object.keys(compatTransforms);
        var result = void 0;
        var extra = {};
        transformToApply.forEach(function(transformName) {
          if (!compatTransforms.hasOwnProperty(transformName)) {
            throw new Error("Unknown compat-transform: " + transformName + ". Available transforms are: " + Object.keys(compatTransforms).join(", "));
          }
          var handler = compatTransforms[transformName];
          result = _transform.transform(regexp, handler);
          regexp = result.getAST();
          if (typeof handler.getExtra === "function") {
            extra[transformName] = handler.getExtra();
          }
        });
        result.setExtra(extra);
        return result;
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/utils/clone.js
var require_clone = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/utils/clone.js"(exports, module) {
    "use strict";
    module.exports = function clone(obj) {
      if (obj === null || typeof obj !== "object") {
        return obj;
      }
      var res = void 0;
      if (Array.isArray(obj)) {
        res = [];
      } else {
        res = {};
      }
      for (var i2 in obj) {
        res[i2] = clone(obj[i2]);
      }
      return res;
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-surrogate-pair-to-single-unicode-transform.js
var require_char_surrogate_pair_to_single_unicode_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-surrogate-pair-to-single-unicode-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      shouldRun: function shouldRun(ast) {
        return ast.flags.includes("u");
      },
      Char: function Char(path) {
        var node = path.node;
        if (node.kind !== "unicode" || !node.isSurrogatePair || isNaN(node.codePoint)) {
          return;
        }
        node.value = "\\u{" + node.codePoint.toString(16) + "}";
        delete node.isSurrogatePair;
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-code-to-simple-char-transform.js
var require_char_code_to_simple_char_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-code-to-simple-char-transform.js"(exports, module) {
    "use strict";
    var UPPER_A_CP = "A".codePointAt(0);
    var UPPER_Z_CP = "Z".codePointAt(0);
    var LOWER_A_CP = "a".codePointAt(0);
    var LOWER_Z_CP = "z".codePointAt(0);
    var DIGIT_0_CP = "0".codePointAt(0);
    var DIGIT_9_CP = "9".codePointAt(0);
    module.exports = {
      Char: function Char(path) {
        var node = path.node, parent = path.parent;
        if (isNaN(node.codePoint) || node.kind === "simple") {
          return;
        }
        if (parent.type === "ClassRange") {
          if (!isSimpleRange(parent)) {
            return;
          }
        }
        if (!isPrintableASCIIChar(node.codePoint)) {
          return;
        }
        var symbol = String.fromCodePoint(node.codePoint);
        var newChar = {
          type: "Char",
          kind: "simple",
          value: symbol,
          symbol,
          codePoint: node.codePoint
        };
        if (needsEscape(symbol, parent.type)) {
          newChar.escaped = true;
        }
        path.replace(newChar);
      }
    };
    function isSimpleRange(classRange) {
      var from = classRange.from, to = classRange.to;
      return from.codePoint >= DIGIT_0_CP && from.codePoint <= DIGIT_9_CP && to.codePoint >= DIGIT_0_CP && to.codePoint <= DIGIT_9_CP || from.codePoint >= UPPER_A_CP && from.codePoint <= UPPER_Z_CP && to.codePoint >= UPPER_A_CP && to.codePoint <= UPPER_Z_CP || from.codePoint >= LOWER_A_CP && from.codePoint <= LOWER_Z_CP && to.codePoint >= LOWER_A_CP && to.codePoint <= LOWER_Z_CP;
    }
    function isPrintableASCIIChar(codePoint) {
      return codePoint >= 32 && codePoint <= 126;
    }
    function needsEscape(symbol, parentType) {
      if (parentType === "ClassRange" || parentType === "CharacterClass") {
        return /[\]\\^-]/.test(symbol);
      }
      return /[*[()+?^$./\\|{}]/.test(symbol);
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-case-insensitive-lowercase-transform.js
var require_char_case_insensitive_lowercase_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-case-insensitive-lowercase-transform.js"(exports, module) {
    "use strict";
    var UPPER_A_CP = "A".codePointAt(0);
    var UPPER_Z_CP = "Z".codePointAt(0);
    module.exports = {
      _AZClassRanges: null,
      _hasUFlag: false,
      init: function init(ast) {
        this._AZClassRanges = /* @__PURE__ */ new Set();
        this._hasUFlag = ast.flags.includes("u");
      },
      shouldRun: function shouldRun(ast) {
        return ast.flags.includes("i");
      },
      Char: function Char(path) {
        var node = path.node, parent = path.parent;
        if (isNaN(node.codePoint)) {
          return;
        }
        if (!this._hasUFlag && node.codePoint >= 4096) {
          return;
        }
        if (parent.type === "ClassRange") {
          if (!this._AZClassRanges.has(parent) && !isAZClassRange(parent)) {
            return;
          }
          this._AZClassRanges.add(parent);
        }
        var lower = node.symbol.toLowerCase();
        if (lower !== node.symbol) {
          node.value = displaySymbolAsValue(lower, node);
          node.symbol = lower;
          node.codePoint = lower.codePointAt(0);
        }
      }
    };
    function isAZClassRange(classRange) {
      var from = classRange.from, to = classRange.to;
      return from.codePoint >= UPPER_A_CP && from.codePoint <= UPPER_Z_CP && to.codePoint >= UPPER_A_CP && to.codePoint <= UPPER_Z_CP;
    }
    function displaySymbolAsValue(symbol, node) {
      var codePoint = symbol.codePointAt(0);
      if (node.kind === "decimal") {
        return "\\" + codePoint;
      }
      if (node.kind === "oct") {
        return "\\0" + codePoint.toString(8);
      }
      if (node.kind === "hex") {
        return "\\x" + codePoint.toString(16);
      }
      if (node.kind === "unicode") {
        if (node.isSurrogatePair) {
          var _getSurrogatePairFrom = getSurrogatePairFromCodePoint(codePoint), lead = _getSurrogatePairFrom.lead, trail = _getSurrogatePairFrom.trail;
          return "\\u" + "0".repeat(4 - lead.length) + lead + "\\u" + "0".repeat(4 - trail.length) + trail;
        } else if (node.value.includes("{")) {
          return "\\u{" + codePoint.toString(16) + "}";
        } else {
          var code = codePoint.toString(16);
          return "\\u" + "0".repeat(4 - code.length) + code;
        }
      }
      return symbol;
    }
    function getSurrogatePairFromCodePoint(codePoint) {
      var lead = Math.floor((codePoint - 65536) / 1024) + 55296;
      var trail = (codePoint - 65536) % 1024 + 56320;
      return {
        lead: lead.toString(16),
        trail: trail.toString(16)
      };
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-remove-duplicates-transform.js
var require_char_class_remove_duplicates_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-remove-duplicates-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      CharacterClass: function CharacterClass(path) {
        var node = path.node;
        var sources = {};
        for (var i2 = 0; i2 < node.expressions.length; i2++) {
          var childPath = path.getChild(i2);
          var source = childPath.jsonEncode();
          if (sources.hasOwnProperty(source)) {
            childPath.remove();
            i2--;
          }
          sources[source] = true;
        }
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/transform/utils.js
var require_utils = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/transform/utils.js"(exports, module) {
    "use strict";
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    function disjunctionToList(node) {
      if (node.type !== "Disjunction") {
        throw new TypeError('Expected "Disjunction" node, got "' + node.type + '"');
      }
      var list = [];
      if (node.left && node.left.type === "Disjunction") {
        list.push.apply(list, _toConsumableArray(disjunctionToList(node.left)).concat([node.right]));
      } else {
        list.push(node.left, node.right);
      }
      return list;
    }
    function listToDisjunction(list) {
      return list.reduce(function(left, right) {
        return {
          type: "Disjunction",
          left,
          right
        };
      });
    }
    function increaseQuantifierByOne(quantifier) {
      if (quantifier.kind === "*") {
        quantifier.kind = "+";
      } else if (quantifier.kind === "+") {
        quantifier.kind = "Range";
        quantifier.from = 2;
        delete quantifier.to;
      } else if (quantifier.kind === "?") {
        quantifier.kind = "Range";
        quantifier.from = 1;
        quantifier.to = 2;
      } else if (quantifier.kind === "Range") {
        quantifier.from += 1;
        if (quantifier.to) {
          quantifier.to += 1;
        }
      }
    }
    module.exports = {
      disjunctionToList,
      listToDisjunction,
      increaseQuantifierByOne
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/quantifiers-merge-transform.js
var require_quantifiers_merge_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/quantifiers-merge-transform.js"(exports, module) {
    "use strict";
    var _require = require_utils();
    var increaseQuantifierByOne = _require.increaseQuantifierByOne;
    module.exports = {
      Repetition: function Repetition(path) {
        var node = path.node, parent = path.parent;
        if (parent.type !== "Alternative" || !path.index) {
          return;
        }
        var previousSibling = path.getPreviousSibling();
        if (!previousSibling) {
          return;
        }
        if (previousSibling.node.type === "Repetition") {
          if (!previousSibling.getChild().hasEqualSource(path.getChild())) {
            return;
          }
          var _extractFromTo = extractFromTo(previousSibling.node.quantifier), previousSiblingFrom = _extractFromTo.from, previousSiblingTo = _extractFromTo.to;
          var _extractFromTo2 = extractFromTo(node.quantifier), nodeFrom = _extractFromTo2.from, nodeTo = _extractFromTo2.to;
          if (previousSibling.node.quantifier.greedy !== node.quantifier.greedy && !isGreedyOpenRange(previousSibling.node.quantifier) && !isGreedyOpenRange(node.quantifier)) {
            return;
          }
          node.quantifier.kind = "Range";
          node.quantifier.from = previousSiblingFrom + nodeFrom;
          if (previousSiblingTo && nodeTo) {
            node.quantifier.to = previousSiblingTo + nodeTo;
          } else {
            delete node.quantifier.to;
          }
          if (isGreedyOpenRange(previousSibling.node.quantifier) || isGreedyOpenRange(node.quantifier)) {
            node.quantifier.greedy = true;
          }
          previousSibling.remove();
        } else {
          if (!previousSibling.hasEqualSource(path.getChild())) {
            return;
          }
          increaseQuantifierByOne(node.quantifier);
          previousSibling.remove();
        }
      }
    };
    function isGreedyOpenRange(quantifier) {
      return quantifier.greedy && (quantifier.kind === "+" || quantifier.kind === "*" || quantifier.kind === "Range" && !quantifier.to);
    }
    function extractFromTo(quantifier) {
      var from = void 0, to = void 0;
      if (quantifier.kind === "*") {
        from = 0;
      } else if (quantifier.kind === "+") {
        from = 1;
      } else if (quantifier.kind === "?") {
        from = 0;
        to = 1;
      } else {
        from = quantifier.from;
        if (quantifier.to) {
          to = quantifier.to;
        }
      }
      return { from, to };
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/quantifier-range-to-symbol-transform.js
var require_quantifier_range_to_symbol_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/quantifier-range-to-symbol-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      Quantifier: function Quantifier(path) {
        var node = path.node;
        if (node.kind !== "Range") {
          return;
        }
        rewriteOpenZero(path);
        rewriteOpenOne(path);
        rewriteExactOne(path);
      }
    };
    function rewriteOpenZero(path) {
      var node = path.node;
      if (node.from !== 0 || node.to) {
        return;
      }
      node.kind = "*";
      delete node.from;
    }
    function rewriteOpenOne(path) {
      var node = path.node;
      if (node.from !== 1 || node.to) {
        return;
      }
      node.kind = "+";
      delete node.from;
    }
    function rewriteExactOne(path) {
      var node = path.node;
      if (node.from !== 1 || node.to !== 1) {
        return;
      }
      path.parentPath.replace(path.parentPath.node.expression);
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-classranges-to-chars-transform.js
var require_char_class_classranges_to_chars_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-classranges-to-chars-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      ClassRange: function ClassRange(path) {
        var node = path.node;
        if (node.from.codePoint === node.to.codePoint) {
          path.replace(node.from);
        } else if (node.from.codePoint === node.to.codePoint - 1) {
          path.getParent().insertChildAt(node.to, path.index + 1);
          path.replace(node.from);
        }
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-to-meta-transform.js
var require_char_class_to_meta_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-to-meta-transform.js"(exports, module) {
    "use strict";
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    module.exports = {
      _hasIFlag: false,
      _hasUFlag: false,
      init: function init(ast) {
        this._hasIFlag = ast.flags.includes("i");
        this._hasUFlag = ast.flags.includes("u");
      },
      CharacterClass: function CharacterClass(path) {
        rewriteNumberRanges(path);
        rewriteWordRanges(path, this._hasIFlag, this._hasUFlag);
        rewriteWhitespaceRanges(path);
      }
    };
    function rewriteNumberRanges(path) {
      var node = path.node;
      node.expressions.forEach(function(expression, i2) {
        if (isFullNumberRange(expression)) {
          path.getChild(i2).replace({
            type: "Char",
            value: "\\d",
            kind: "meta"
          });
        }
      });
    }
    function rewriteWordRanges(path, hasIFlag, hasUFlag) {
      var node = path.node;
      var numberPath = null;
      var lowerCasePath = null;
      var upperCasePath = null;
      var underscorePath = null;
      var u017fPath = null;
      var u212aPath = null;
      node.expressions.forEach(function(expression, i2) {
        if (isMetaChar(expression, "\\d")) {
          numberPath = path.getChild(i2);
        } else if (isLowerCaseRange(expression)) {
          lowerCasePath = path.getChild(i2);
        } else if (isUpperCaseRange(expression)) {
          upperCasePath = path.getChild(i2);
        } else if (isUnderscore(expression)) {
          underscorePath = path.getChild(i2);
        } else if (hasIFlag && hasUFlag && isCodePoint(expression, 383)) {
          u017fPath = path.getChild(i2);
        } else if (hasIFlag && hasUFlag && isCodePoint(expression, 8490)) {
          u212aPath = path.getChild(i2);
        }
      });
      if (numberPath && (lowerCasePath && upperCasePath || hasIFlag && (lowerCasePath || upperCasePath)) && underscorePath && (!hasUFlag || !hasIFlag || u017fPath && u212aPath)) {
        numberPath.replace({
          type: "Char",
          value: "\\w",
          kind: "meta"
        });
        if (lowerCasePath) {
          lowerCasePath.remove();
        }
        if (upperCasePath) {
          upperCasePath.remove();
        }
        underscorePath.remove();
        if (u017fPath) {
          u017fPath.remove();
        }
        if (u212aPath) {
          u212aPath.remove();
        }
      }
    }
    var whitespaceRangeTests = [function(node) {
      return isChar(node, " ");
    }].concat(_toConsumableArray(["\\f", "\\n", "\\r", "\\t", "\\v"].map(function(char) {
      return function(node) {
        return isMetaChar(node, char);
      };
    })), _toConsumableArray([160, 5760, 8232, 8233, 8239, 8287, 12288, 65279].map(function(codePoint) {
      return function(node) {
        return isCodePoint(node, codePoint);
      };
    })), [function(node) {
      return node.type === "ClassRange" && isCodePoint(node.from, 8192) && isCodePoint(node.to, 8202);
    }]);
    function rewriteWhitespaceRanges(path) {
      var node = path.node;
      if (node.expressions.length < whitespaceRangeTests.length || !whitespaceRangeTests.every(function(test) {
        return node.expressions.some(function(expression) {
          return test(expression);
        });
      })) {
        return;
      }
      var nNode = node.expressions.find(function(expression) {
        return isMetaChar(expression, "\\n");
      });
      nNode.value = "\\s";
      nNode.symbol = void 0;
      nNode.codePoint = NaN;
      node.expressions.map(function(expression, i2) {
        return whitespaceRangeTests.some(function(test) {
          return test(expression);
        }) ? path.getChild(i2) : void 0;
      }).filter(Boolean).forEach(function(path2) {
        return path2.remove();
      });
    }
    function isFullNumberRange(node) {
      return node.type === "ClassRange" && node.from.value === "0" && node.to.value === "9";
    }
    function isChar(node, value) {
      var kind = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : "simple";
      return node.type === "Char" && node.value === value && node.kind === kind;
    }
    function isMetaChar(node, value) {
      return isChar(node, value, "meta");
    }
    function isLowerCaseRange(node) {
      return node.type === "ClassRange" && node.from.value === "a" && node.to.value === "z";
    }
    function isUpperCaseRange(node) {
      return node.type === "ClassRange" && node.from.value === "A" && node.to.value === "Z";
    }
    function isUnderscore(node) {
      return node.type === "Char" && node.value === "_" && node.kind === "simple";
    }
    function isCodePoint(node, codePoint) {
      return node.type === "Char" && node.kind === "unicode" && node.codePoint === codePoint;
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-to-single-char-transform.js
var require_char_class_to_single_char_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-to-single-char-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      CharacterClass: function CharacterClass(path) {
        var node = path.node;
        if (node.expressions.length !== 1 || !hasAppropriateSiblings(path) || !isAppropriateChar(node.expressions[0])) {
          return;
        }
        var _node$expressions$ = node.expressions[0], value = _node$expressions$.value, kind = _node$expressions$.kind, escaped = _node$expressions$.escaped;
        if (node.negative) {
          if (!isMeta(value)) {
            return;
          }
          value = getInverseMeta(value);
        }
        path.replace({
          type: "Char",
          value,
          kind,
          escaped: escaped || shouldEscape(value)
        });
      }
    };
    function isAppropriateChar(node) {
      return node.type === "Char" && // We don't extract [\b] (backspace) since \b has different
      // semantics (word boundary).
      node.value !== "\\b";
    }
    function isMeta(value) {
      return /^\\[dwsDWS]$/.test(value);
    }
    function getInverseMeta(value) {
      return /[dws]/.test(value) ? value.toUpperCase() : value.toLowerCase();
    }
    function hasAppropriateSiblings(path) {
      var parent = path.parent, index = path.index;
      if (parent.type !== "Alternative") {
        return true;
      }
      var previousNode = parent.expressions[index - 1];
      if (previousNode == null) {
        return true;
      }
      if (previousNode.type === "Backreference" && previousNode.kind === "number") {
        return false;
      }
      if (previousNode.type === "Char" && previousNode.kind === "decimal") {
        return false;
      }
      return true;
    }
    function shouldEscape(value) {
      return /[*[()+?$./{}|]/.test(value);
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-escape-unescape-transform.js
var require_char_escape_unescape_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-escape-unescape-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      _hasXFlag: false,
      init: function init(ast) {
        this._hasXFlag = ast.flags.includes("x");
      },
      Char: function Char(path) {
        var node = path.node;
        if (!node.escaped) {
          return;
        }
        if (shouldUnescape(path, this._hasXFlag)) {
          delete node.escaped;
        }
      }
    };
    function shouldUnescape(path, hasXFlag) {
      var value = path.node.value, index = path.index, parent = path.parent;
      if (parent.type !== "CharacterClass" && parent.type !== "ClassRange") {
        return !preservesEscape(value, index, parent, hasXFlag);
      }
      return !preservesInCharClass(value, index, parent);
    }
    function preservesInCharClass(value, index, parent) {
      if (value === "^") {
        return index === 0 && !parent.negative;
      }
      if (value === "-") {
        return true;
      }
      return /[\]\\]/.test(value);
    }
    function preservesEscape(value, index, parent, hasXFlag) {
      if (value === "{") {
        return preservesOpeningCurlyBraceEscape(index, parent);
      }
      if (value === "}") {
        return preservesClosingCurlyBraceEscape(index, parent);
      }
      if (hasXFlag && /[ #]/.test(value)) {
        return true;
      }
      return /[*[()+?^$./\\|]/.test(value);
    }
    function consumeNumbers(startIndex, parent, rtl) {
      var i2 = startIndex;
      var siblingNode = (rtl ? i2 >= 0 : i2 < parent.expressions.length) && parent.expressions[i2];
      while (siblingNode && siblingNode.type === "Char" && siblingNode.kind === "simple" && !siblingNode.escaped && /\d/.test(siblingNode.value)) {
        rtl ? i2-- : i2++;
        siblingNode = (rtl ? i2 >= 0 : i2 < parent.expressions.length) && parent.expressions[i2];
      }
      return Math.abs(startIndex - i2);
    }
    function isSimpleChar(node, value) {
      return node && node.type === "Char" && node.kind === "simple" && !node.escaped && node.value === value;
    }
    function preservesOpeningCurlyBraceEscape(index, parent) {
      if (index == null) {
        return false;
      }
      var nbFollowingNumbers = consumeNumbers(index + 1, parent);
      var i2 = index + nbFollowingNumbers + 1;
      var nextSiblingNode = i2 < parent.expressions.length && parent.expressions[i2];
      if (nbFollowingNumbers) {
        if (isSimpleChar(nextSiblingNode, "}")) {
          return true;
        }
        if (isSimpleChar(nextSiblingNode, ",")) {
          nbFollowingNumbers = consumeNumbers(i2 + 1, parent);
          i2 = i2 + nbFollowingNumbers + 1;
          nextSiblingNode = i2 < parent.expressions.length && parent.expressions[i2];
          return isSimpleChar(nextSiblingNode, "}");
        }
      }
      return false;
    }
    function preservesClosingCurlyBraceEscape(index, parent) {
      if (index == null) {
        return false;
      }
      var nbPrecedingNumbers = consumeNumbers(index - 1, parent, true);
      var i2 = index - nbPrecedingNumbers - 1;
      var previousSiblingNode = i2 >= 0 && parent.expressions[i2];
      if (nbPrecedingNumbers && isSimpleChar(previousSiblingNode, "{")) {
        return true;
      }
      if (isSimpleChar(previousSiblingNode, ",")) {
        nbPrecedingNumbers = consumeNumbers(i2 - 1, parent, true);
        i2 = i2 - nbPrecedingNumbers - 1;
        previousSiblingNode = i2 < parent.expressions.length && parent.expressions[i2];
        return nbPrecedingNumbers && isSimpleChar(previousSiblingNode, "{");
      }
      return false;
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-classranges-merge-transform.js
var require_char_class_classranges_merge_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/char-class-classranges-merge-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      _hasIUFlags: false,
      init: function init(ast) {
        this._hasIUFlags = ast.flags.includes("i") && ast.flags.includes("u");
      },
      CharacterClass: function CharacterClass(path) {
        var node = path.node;
        var expressions = node.expressions;
        var metas = [];
        expressions.forEach(function(expression2) {
          if (isMeta(expression2)) {
            metas.push(expression2.value);
          }
        });
        expressions.sort(sortCharClass);
        for (var i2 = 0; i2 < expressions.length; i2++) {
          var expression = expressions[i2];
          if (fitsInMetas(expression, metas, this._hasIUFlags) || combinesWithPrecedingClassRange(expression, expressions[i2 - 1]) || combinesWithFollowingClassRange(expression, expressions[i2 + 1])) {
            expressions.splice(i2, 1);
            i2--;
          } else {
            var nbMergedChars = charCombinesWithPrecedingChars(expression, i2, expressions);
            expressions.splice(i2 - nbMergedChars + 1, nbMergedChars);
            i2 -= nbMergedChars;
          }
        }
      }
    };
    function sortCharClass(a, b) {
      var aValue = getSortValue(a);
      var bValue = getSortValue(b);
      if (aValue === bValue) {
        if (a.type === "ClassRange" && b.type !== "ClassRange") {
          return -1;
        }
        if (b.type === "ClassRange" && a.type !== "ClassRange") {
          return 1;
        }
        if (a.type === "ClassRange" && b.type === "ClassRange") {
          return getSortValue(a.to) - getSortValue(b.to);
        }
        if (isMeta(a) && isMeta(b) || isControl(a) && isControl(b)) {
          return a.value < b.value ? -1 : 1;
        }
      }
      return aValue - bValue;
    }
    function getSortValue(expression) {
      if (expression.type === "Char") {
        if (expression.value === "-") {
          return Infinity;
        }
        if (expression.kind === "control") {
          return Infinity;
        }
        if (expression.kind === "meta" && isNaN(expression.codePoint)) {
          return -1;
        }
        return expression.codePoint;
      }
      return expression.from.codePoint;
    }
    function isMeta(expression) {
      var value = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : null;
      return expression.type === "Char" && expression.kind === "meta" && (value ? expression.value === value : /^\\[dws]$/i.test(expression.value));
    }
    function isControl(expression) {
      return expression.type === "Char" && expression.kind === "control";
    }
    function fitsInMetas(expression, metas, hasIUFlags) {
      for (var i2 = 0; i2 < metas.length; i2++) {
        if (fitsInMeta(expression, metas[i2], hasIUFlags)) {
          return true;
        }
      }
      return false;
    }
    function fitsInMeta(expression, meta, hasIUFlags) {
      if (expression.type === "ClassRange") {
        return fitsInMeta(expression.from, meta, hasIUFlags) && fitsInMeta(expression.to, meta, hasIUFlags);
      }
      if (meta === "\\S" && (isMeta(expression, "\\w") || isMeta(expression, "\\d"))) {
        return true;
      }
      if (meta === "\\D" && (isMeta(expression, "\\W") || isMeta(expression, "\\s"))) {
        return true;
      }
      if (meta === "\\w" && isMeta(expression, "\\d")) {
        return true;
      }
      if (meta === "\\W" && isMeta(expression, "\\s")) {
        return true;
      }
      if (expression.type !== "Char" || isNaN(expression.codePoint)) {
        return false;
      }
      if (meta === "\\s") {
        return fitsInMetaS(expression);
      }
      if (meta === "\\S") {
        return !fitsInMetaS(expression);
      }
      if (meta === "\\d") {
        return fitsInMetaD(expression);
      }
      if (meta === "\\D") {
        return !fitsInMetaD(expression);
      }
      if (meta === "\\w") {
        return fitsInMetaW(expression, hasIUFlags);
      }
      if (meta === "\\W") {
        return !fitsInMetaW(expression, hasIUFlags);
      }
      return false;
    }
    function fitsInMetaS(expression) {
      return expression.codePoint === 9 || // \t
      expression.codePoint === 10 || // \n
      expression.codePoint === 11 || // \v
      expression.codePoint === 12 || // \f
      expression.codePoint === 13 || // \r
      expression.codePoint === 32 || // space
      expression.codePoint === 160 || // nbsp
      expression.codePoint === 5760 || // part of Zs
      expression.codePoint >= 8192 && expression.codePoint <= 8202 || // part of Zs
      expression.codePoint === 8232 || // line separator
      expression.codePoint === 8233 || // paragraph separator
      expression.codePoint === 8239 || // part of Zs
      expression.codePoint === 8287 || // part of Zs
      expression.codePoint === 12288 || // part of Zs
      expression.codePoint === 65279;
    }
    function fitsInMetaD(expression) {
      return expression.codePoint >= 48 && expression.codePoint <= 57;
    }
    function fitsInMetaW(expression, hasIUFlags) {
      return fitsInMetaD(expression) || expression.codePoint >= 65 && expression.codePoint <= 90 || // A-Z
      expression.codePoint >= 97 && expression.codePoint <= 122 || // a-z
      expression.value === "_" || hasIUFlags && (expression.codePoint === 383 || expression.codePoint === 8490);
    }
    function combinesWithPrecedingClassRange(expression, classRange) {
      if (classRange && classRange.type === "ClassRange") {
        if (fitsInClassRange(expression, classRange)) {
          return true;
        } else if (
          // We only want \w chars or char codes to keep readability
          isMetaWCharOrCode(expression) && classRange.to.codePoint === expression.codePoint - 1
        ) {
          classRange.to = expression;
          return true;
        } else if (expression.type === "ClassRange" && expression.from.codePoint <= classRange.to.codePoint + 1 && expression.to.codePoint >= classRange.from.codePoint - 1) {
          if (expression.from.codePoint < classRange.from.codePoint) {
            classRange.from = expression.from;
          }
          if (expression.to.codePoint > classRange.to.codePoint) {
            classRange.to = expression.to;
          }
          return true;
        }
      }
      return false;
    }
    function combinesWithFollowingClassRange(expression, classRange) {
      if (classRange && classRange.type === "ClassRange") {
        if (
          // We only want \w chars or char codes to keep readability
          isMetaWCharOrCode(expression) && classRange.from.codePoint === expression.codePoint + 1
        ) {
          classRange.from = expression;
          return true;
        }
      }
      return false;
    }
    function fitsInClassRange(expression, classRange) {
      if (expression.type === "Char" && isNaN(expression.codePoint)) {
        return false;
      }
      if (expression.type === "ClassRange") {
        return fitsInClassRange(expression.from, classRange) && fitsInClassRange(expression.to, classRange);
      }
      return expression.codePoint >= classRange.from.codePoint && expression.codePoint <= classRange.to.codePoint;
    }
    function charCombinesWithPrecedingChars(expression, index, expressions) {
      if (!isMetaWCharOrCode(expression)) {
        return 0;
      }
      var nbMergedChars = 0;
      while (index > 0) {
        var currentExpression = expressions[index];
        var precedingExpresion = expressions[index - 1];
        if (isMetaWCharOrCode(precedingExpresion) && precedingExpresion.codePoint === currentExpression.codePoint - 1) {
          nbMergedChars++;
          index--;
        } else {
          break;
        }
      }
      if (nbMergedChars > 1) {
        expressions[index] = {
          type: "ClassRange",
          from: expressions[index],
          to: expression
        };
        return nbMergedChars;
      }
      return 0;
    }
    function isMetaWCharOrCode(expression) {
      return expression && expression.type === "Char" && !isNaN(expression.codePoint) && (fitsInMetaW(expression, false) || expression.kind === "unicode" || expression.kind === "hex" || expression.kind === "oct" || expression.kind === "decimal");
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/disjunction-remove-duplicates-transform.js
var require_disjunction_remove_duplicates_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/disjunction-remove-duplicates-transform.js"(exports, module) {
    "use strict";
    var NodePath = require_node_path();
    var _require = require_utils();
    var disjunctionToList = _require.disjunctionToList;
    var listToDisjunction = _require.listToDisjunction;
    module.exports = {
      Disjunction: function Disjunction(path) {
        var node = path.node;
        var uniqueNodesMap = {};
        var parts = disjunctionToList(node).filter(function(part) {
          var encoded = part ? NodePath.getForNode(part).jsonEncode() : "null";
          if (uniqueNodesMap.hasOwnProperty(encoded)) {
            return false;
          }
          uniqueNodesMap[encoded] = part;
          return true;
        });
        path.replace(listToDisjunction(parts));
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/group-single-chars-to-char-class.js
var require_group_single_chars_to_char_class = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/group-single-chars-to-char-class.js"(exports, module) {
    "use strict";
    module.exports = {
      Disjunction: function Disjunction(path) {
        var node = path.node, parent = path.parent;
        if (!handlers[parent.type]) {
          return;
        }
        var charset = /* @__PURE__ */ new Map();
        if (!shouldProcess(node, charset) || !charset.size) {
          return;
        }
        var characterClass = {
          type: "CharacterClass",
          expressions: Array.from(charset.keys()).sort().map(function(key) {
            return charset.get(key);
          })
        };
        handlers[parent.type](path.getParent(), characterClass);
      }
    };
    var handlers = {
      RegExp: function RegExp2(path, characterClass) {
        var node = path.node;
        node.body = characterClass;
      },
      Group: function Group(path, characterClass) {
        var node = path.node;
        if (node.capturing) {
          node.expression = characterClass;
        } else {
          path.replace(characterClass);
        }
      }
    };
    function shouldProcess(expression, charset) {
      if (!expression) {
        return false;
      }
      var type2 = expression.type;
      if (type2 === "Disjunction") {
        var left = expression.left, right = expression.right;
        return shouldProcess(left, charset) && shouldProcess(right, charset);
      } else if (type2 === "Char") {
        if (expression.kind === "meta" && expression.symbol === ".") {
          return false;
        }
        var value = expression.value;
        charset.set(value, expression);
        return true;
      } else if (type2 === "CharacterClass" && !expression.negative) {
        return expression.expressions.every(function(expression2) {
          return shouldProcess(expression2, charset);
        });
      }
      return false;
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/remove-empty-group-transform.js
var require_remove_empty_group_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/remove-empty-group-transform.js"(exports, module) {
    "use strict";
    module.exports = {
      Group: function Group(path) {
        var node = path.node, parent = path.parent;
        var childPath = path.getChild();
        if (node.capturing || childPath) {
          return;
        }
        if (parent.type === "Repetition") {
          path.getParent().replace(node);
        } else if (parent.type !== "RegExp") {
          path.remove();
        }
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/ungroup-transform.js
var require_ungroup_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/ungroup-transform.js"(exports, module) {
    "use strict";
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    module.exports = {
      Group: function Group(path) {
        var node = path.node, parent = path.parent;
        var childPath = path.getChild();
        if (node.capturing || !childPath) {
          return;
        }
        if (!hasAppropriateSiblings(path)) {
          return;
        }
        if (childPath.node.type === "Disjunction" && parent.type !== "RegExp") {
          return;
        }
        if (parent.type === "Repetition" && childPath.node.type !== "Char" && childPath.node.type !== "CharacterClass") {
          return;
        }
        if (childPath.node.type === "Alternative") {
          var parentPath = path.getParent();
          if (parentPath.node.type === "Alternative") {
            parentPath.replace({
              type: "Alternative",
              expressions: [].concat(_toConsumableArray(parent.expressions.slice(0, path.index)), _toConsumableArray(childPath.node.expressions), _toConsumableArray(parent.expressions.slice(path.index + 1)))
            });
          }
        } else {
          path.replace(childPath.node);
        }
      }
    };
    function hasAppropriateSiblings(path) {
      var parent = path.parent, index = path.index;
      if (parent.type !== "Alternative") {
        return true;
      }
      var previousNode = parent.expressions[index - 1];
      if (previousNode == null) {
        return true;
      }
      if (previousNode.type === "Backreference" && previousNode.kind === "number") {
        return false;
      }
      if (previousNode.type === "Char" && previousNode.kind === "decimal") {
        return false;
      }
      return true;
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/combine-repeating-patterns-transform.js
var require_combine_repeating_patterns_transform = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/combine-repeating-patterns-transform.js"(exports, module) {
    "use strict";
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    var NodePath = require_node_path();
    var _require = require_utils();
    var increaseQuantifierByOne = _require.increaseQuantifierByOne;
    module.exports = {
      Alternative: function Alternative(path) {
        var node = path.node;
        var index = 1;
        while (index < node.expressions.length) {
          var child = path.getChild(index);
          index = Math.max(1, combineRepeatingPatternLeft(path, child, index));
          if (index >= node.expressions.length) {
            break;
          }
          child = path.getChild(index);
          index = Math.max(1, combineWithPreviousRepetition(path, child, index));
          if (index >= node.expressions.length) {
            break;
          }
          child = path.getChild(index);
          index = Math.max(1, combineRepetitionWithPrevious(path, child, index));
          index++;
        }
      }
    };
    function combineRepeatingPatternLeft(alternative, child, index) {
      var node = alternative.node;
      var nbPossibleLengths = Math.ceil(index / 2);
      var i2 = 0;
      while (i2 < nbPossibleLengths) {
        var startIndex = index - 2 * i2 - 1;
        var right = void 0, left = void 0;
        if (i2 === 0) {
          right = child;
          left = alternative.getChild(startIndex);
        } else {
          right = NodePath.getForNode({
            type: "Alternative",
            expressions: [].concat(_toConsumableArray(node.expressions.slice(index - i2, index)), [child.node])
          });
          left = NodePath.getForNode({
            type: "Alternative",
            expressions: [].concat(_toConsumableArray(node.expressions.slice(startIndex, index - i2)))
          });
        }
        if (right.hasEqualSource(left)) {
          for (var j = 0; j < 2 * i2 + 1; j++) {
            alternative.getChild(startIndex).remove();
          }
          child.replace({
            type: "Repetition",
            expression: i2 === 0 && right.node.type !== "Repetition" ? right.node : {
              type: "Group",
              capturing: false,
              expression: right.node
            },
            quantifier: {
              type: "Quantifier",
              kind: "Range",
              from: 2,
              to: 2,
              greedy: true
            }
          });
          return startIndex;
        }
        i2++;
      }
      return index;
    }
    function combineWithPreviousRepetition(alternative, child, index) {
      var node = alternative.node;
      var i2 = 0;
      while (i2 < index) {
        var previousChild = alternative.getChild(i2);
        if (previousChild.node.type === "Repetition" && previousChild.node.quantifier.greedy) {
          var left = previousChild.getChild();
          var right = void 0;
          if (left.node.type === "Group" && !left.node.capturing) {
            left = left.getChild();
          }
          if (i2 + 1 === index) {
            right = child;
            if (right.node.type === "Group" && !right.node.capturing) {
              right = right.getChild();
            }
          } else {
            right = NodePath.getForNode({
              type: "Alternative",
              expressions: [].concat(_toConsumableArray(node.expressions.slice(i2 + 1, index + 1)))
            });
          }
          if (left.hasEqualSource(right)) {
            for (var j = i2; j < index; j++) {
              alternative.getChild(i2 + 1).remove();
            }
            increaseQuantifierByOne(previousChild.node.quantifier);
            return i2;
          }
        }
        i2++;
      }
      return index;
    }
    function combineRepetitionWithPrevious(alternative, child, index) {
      var node = alternative.node;
      if (child.node.type === "Repetition" && child.node.quantifier.greedy) {
        var right = child.getChild();
        var left = void 0;
        if (right.node.type === "Group" && !right.node.capturing) {
          right = right.getChild();
        }
        var rightLength = void 0;
        if (right.node.type === "Alternative") {
          rightLength = right.node.expressions.length;
          left = NodePath.getForNode({
            type: "Alternative",
            expressions: [].concat(_toConsumableArray(node.expressions.slice(index - rightLength, index)))
          });
        } else {
          rightLength = 1;
          left = alternative.getChild(index - 1);
          if (left.node.type === "Group" && !left.node.capturing) {
            left = left.getChild();
          }
        }
        if (left.hasEqualSource(right)) {
          for (var j = index - rightLength; j < index; j++) {
            alternative.getChild(index - rightLength).remove();
          }
          increaseQuantifierByOne(child.node.quantifier);
          return index - rightLength;
        }
      }
      return index;
    }
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/index.js
var require_transforms2 = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/transforms/index.js"(exports, module) {
    "use strict";
    module.exports = /* @__PURE__ */ new Map([
      // \ud83d\ude80 -> \u{1f680}
      ["charSurrogatePairToSingleUnicode", require_char_surrogate_pair_to_single_unicode_transform()],
      // \u0061 -> a
      ["charCodeToSimpleChar", require_char_code_to_simple_char_transform()],
      // /Aa/i -> /aa/i
      ["charCaseInsensitiveLowerCaseTransform", require_char_case_insensitive_lowercase_transform()],
      // [\d\d] -> [\d]
      ["charClassRemoveDuplicates", require_char_class_remove_duplicates_transform()],
      // a{1,2}a{2,3} -> a{3,5}
      ["quantifiersMerge", require_quantifiers_merge_transform()],
      // a{1,} -> a+, a{3,3} -> a{3}, a{1} -> a
      ["quantifierRangeToSymbol", require_quantifier_range_to_symbol_transform()],
      // [a-a] -> [a], [a-b] -> [ab]
      ["charClassClassrangesToChars", require_char_class_classranges_to_chars_transform()],
      // [0-9] -> [\d]
      ["charClassToMeta", require_char_class_to_meta_transform()],
      // [\d] -> \d, [^\w] -> \W
      ["charClassToSingleChar", require_char_class_to_single_char_transform()],
      // \e -> e
      ["charEscapeUnescape", require_char_escape_unescape_transform()],
      // [a-de-f] -> [a-f]
      ["charClassClassrangesMerge", require_char_class_classranges_merge_transform()],
      // (ab|ab) -> (ab)
      ["disjunctionRemoveDuplicates", require_disjunction_remove_duplicates_transform()],
      // (a|b|c) -> [abc]
      ["groupSingleCharsToCharClass", require_group_single_chars_to_char_class()],
      // (?:)a -> a
      ["removeEmptyGroup", require_remove_empty_group_transform()],
      // (?:a) -> a
      ["ungroup", require_ungroup_transform()],
      // abcabcabc -> (?:abc){3}
      ["combineRepeatingPatterns", require_combine_repeating_patterns_transform()]
    ]);
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/index.js
var require_optimizer = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/optimizer/index.js"(exports, module) {
    "use strict";
    var clone = require_clone();
    var parser = require_parser();
    var transform = require_transform();
    var optimizationTransforms = require_transforms2();
    module.exports = {
      /**
       * Optimizer transforms a regular expression into an optimized version,
       * replacing some sub-expressions with their idiomatic patterns.
       *
       * @param string | RegExp | AST - a regexp to optimize.
       *
       * @return TransformResult - an optimized regexp.
       *
       * Example:
       *
       *   /[a-zA-Z_0-9][a-zA-Z_0-9]*\e{1,}/
       *
       * Optimized to:
       *
       *   /\w+e+/
       */
      optimize: function optimize(regexp) {
        var _ref = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : {}, _ref$whitelist = _ref.whitelist, whitelist = _ref$whitelist === void 0 ? [] : _ref$whitelist, _ref$blacklist = _ref.blacklist, blacklist = _ref$blacklist === void 0 ? [] : _ref$blacklist;
        var transformsRaw = whitelist.length > 0 ? whitelist : Array.from(optimizationTransforms.keys());
        var transformToApply = transformsRaw.filter(function(transform2) {
          return !blacklist.includes(transform2);
        });
        var ast = regexp;
        if (regexp instanceof RegExp) {
          regexp = "" + regexp;
        }
        if (typeof regexp === "string") {
          ast = parser.parse(regexp);
        }
        var result = new transform.TransformResult(ast);
        var prevResultString = void 0;
        do {
          prevResultString = result.toString();
          ast = clone(result.getAST());
          transformToApply.forEach(function(transformName) {
            if (!optimizationTransforms.has(transformName)) {
              throw new Error("Unknown optimization-transform: " + transformName + ". Available transforms are: " + Array.from(optimizationTransforms.keys()).join(", "));
            }
            var transformer = optimizationTransforms.get(transformName);
            var newResult = transform.transform(ast, transformer);
            if (newResult.toString() !== result.toString()) {
              if (newResult.toString().length <= result.toString().length) {
                result = newResult;
              } else {
                ast = clone(result.getAST());
              }
            }
          });
        } while (result.toString() !== prevResultString);
        return result;
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/special-symbols.js
var require_special_symbols = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/special-symbols.js"(exports, module) {
    "use strict";
    var EPSILON = "\u03B5";
    var EPSILON_CLOSURE = EPSILON + "*";
    module.exports = {
      EPSILON,
      EPSILON_CLOSURE
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/nfa/nfa.js
var require_nfa = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/nfa/nfa.js"(exports, module) {
    "use strict";
    var _slicedToArray = /* @__PURE__ */ (function() {
      function sliceIterator(arr, i2) {
        var _arr = [];
        var _n = true;
        var _d = false;
        var _e = void 0;
        try {
          for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) {
            _arr.push(_s.value);
            if (i2 && _arr.length === i2) break;
          }
        } catch (err) {
          _d = true;
          _e = err;
        } finally {
          try {
            if (!_n && _i["return"]) _i["return"]();
          } finally {
            if (_d) throw _e;
          }
        }
        return _arr;
      }
      return function(arr, i2) {
        if (Array.isArray(arr)) {
          return arr;
        } else if (Symbol.iterator in Object(arr)) {
          return sliceIterator(arr, i2);
        } else {
          throw new TypeError("Invalid attempt to destructure non-iterable instance");
        }
      };
    })();
    var _createClass = /* @__PURE__ */ (function() {
      function defineProperties(target, props) {
        for (var i2 = 0; i2 < props.length; i2++) {
          var descriptor = props[i2];
          descriptor.enumerable = descriptor.enumerable || false;
          descriptor.configurable = true;
          if ("value" in descriptor) descriptor.writable = true;
          Object.defineProperty(target, descriptor.key, descriptor);
        }
      }
      return function(Constructor, protoProps, staticProps) {
        if (protoProps) defineProperties(Constructor.prototype, protoProps);
        if (staticProps) defineProperties(Constructor, staticProps);
        return Constructor;
      };
    })();
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    function _classCallCheck(instance, Constructor) {
      if (!(instance instanceof Constructor)) {
        throw new TypeError("Cannot call a class as a function");
      }
    }
    var _require = require_special_symbols();
    var EPSILON = _require.EPSILON;
    var EPSILON_CLOSURE = _require.EPSILON_CLOSURE;
    var NFA = (function() {
      function NFA2(inState, outState) {
        _classCallCheck(this, NFA2);
        this.in = inState;
        this.out = outState;
      }
      _createClass(NFA2, [{
        key: "matches",
        value: function matches(string) {
          return this.in.matches(string);
        }
        /**
         * Returns an alphabet for this NFA.
         */
      }, {
        key: "getAlphabet",
        value: function getAlphabet() {
          if (!this._alphabet) {
            this._alphabet = /* @__PURE__ */ new Set();
            var table = this.getTransitionTable();
            for (var state in table) {
              var transitions = table[state];
              for (var symbol in transitions) {
                if (symbol !== EPSILON_CLOSURE) {
                  this._alphabet.add(symbol);
                }
              }
            }
          }
          return this._alphabet;
        }
        /**
         * Returns set of accepting states.
         */
      }, {
        key: "getAcceptingStates",
        value: function getAcceptingStates() {
          if (!this._acceptingStates) {
            this.getTransitionTable();
          }
          return this._acceptingStates;
        }
        /**
         * Returns accepting state numbers.
         */
      }, {
        key: "getAcceptingStateNumbers",
        value: function getAcceptingStateNumbers() {
          if (!this._acceptingStateNumbers) {
            this._acceptingStateNumbers = /* @__PURE__ */ new Set();
            var _iteratorNormalCompletion = true;
            var _didIteratorError = false;
            var _iteratorError = void 0;
            try {
              for (var _iterator = this.getAcceptingStates()[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
                var acceptingState = _step.value;
                this._acceptingStateNumbers.add(acceptingState.number);
              }
            } catch (err) {
              _didIteratorError = true;
              _iteratorError = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion && _iterator.return) {
                  _iterator.return();
                }
              } finally {
                if (_didIteratorError) {
                  throw _iteratorError;
                }
              }
            }
          }
          return this._acceptingStateNumbers;
        }
        /**
         * Builds and returns transition table.
         */
      }, {
        key: "getTransitionTable",
        value: function getTransitionTable() {
          var _this = this;
          if (!this._transitionTable) {
            this._transitionTable = {};
            this._acceptingStates = /* @__PURE__ */ new Set();
            var visited = /* @__PURE__ */ new Set();
            var symbols = /* @__PURE__ */ new Set();
            var visitState = function visitState2(state) {
              if (visited.has(state)) {
                return;
              }
              visited.add(state);
              state.number = visited.size;
              _this._transitionTable[state.number] = {};
              if (state.accepting) {
                _this._acceptingStates.add(state);
              }
              var transitions = state.getTransitions();
              var _iteratorNormalCompletion2 = true;
              var _didIteratorError2 = false;
              var _iteratorError2 = void 0;
              try {
                for (var _iterator2 = transitions[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
                  var _ref = _step2.value;
                  var _ref2 = _slicedToArray(_ref, 2);
                  var symbol = _ref2[0];
                  var symbolTransitions = _ref2[1];
                  var combinedState = [];
                  symbols.add(symbol);
                  var _iteratorNormalCompletion3 = true;
                  var _didIteratorError3 = false;
                  var _iteratorError3 = void 0;
                  try {
                    for (var _iterator3 = symbolTransitions[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
                      var nextState = _step3.value;
                      visitState2(nextState);
                      combinedState.push(nextState.number);
                    }
                  } catch (err) {
                    _didIteratorError3 = true;
                    _iteratorError3 = err;
                  } finally {
                    try {
                      if (!_iteratorNormalCompletion3 && _iterator3.return) {
                        _iterator3.return();
                      }
                    } finally {
                      if (_didIteratorError3) {
                        throw _iteratorError3;
                      }
                    }
                  }
                  _this._transitionTable[state.number][symbol] = combinedState;
                }
              } catch (err) {
                _didIteratorError2 = true;
                _iteratorError2 = err;
              } finally {
                try {
                  if (!_iteratorNormalCompletion2 && _iterator2.return) {
                    _iterator2.return();
                  }
                } finally {
                  if (_didIteratorError2) {
                    throw _iteratorError2;
                  }
                }
              }
            };
            visitState(this.in);
            visited.forEach(function(state) {
              delete _this._transitionTable[state.number][EPSILON];
              _this._transitionTable[state.number][EPSILON_CLOSURE] = [].concat(_toConsumableArray(state.getEpsilonClosure())).map(function(s) {
                return s.number;
              });
            });
          }
          return this._transitionTable;
        }
      }]);
      return NFA2;
    })();
    module.exports = NFA;
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/dfa/dfa-minimizer.js
var require_dfa_minimizer = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/dfa/dfa-minimizer.js"(exports, module) {
    "use strict";
    var _slicedToArray = /* @__PURE__ */ (function() {
      function sliceIterator(arr, i2) {
        var _arr = [];
        var _n = true;
        var _d = false;
        var _e = void 0;
        try {
          for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) {
            _arr.push(_s.value);
            if (i2 && _arr.length === i2) break;
          }
        } catch (err) {
          _d = true;
          _e = err;
        } finally {
          try {
            if (!_n && _i["return"]) _i["return"]();
          } finally {
            if (_d) throw _e;
          }
        }
        return _arr;
      }
      return function(arr, i2) {
        if (Array.isArray(arr)) {
          return arr;
        } else if (Symbol.iterator in Object(arr)) {
          return sliceIterator(arr, i2);
        } else {
          throw new TypeError("Invalid attempt to destructure non-iterable instance");
        }
      };
    })();
    function _toArray(arr) {
      return Array.isArray(arr) ? arr : Array.from(arr);
    }
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    var currentTransitionMap = null;
    function minimize(dfa) {
      var table = dfa.getTransitionTable();
      var allStates = Object.keys(table);
      var alphabet = dfa.getAlphabet();
      var accepting = dfa.getAcceptingStateNumbers();
      currentTransitionMap = {};
      var nonAccepting = /* @__PURE__ */ new Set();
      allStates.forEach(function(state) {
        state = Number(state);
        var isAccepting = accepting.has(state);
        if (isAccepting) {
          currentTransitionMap[state] = accepting;
        } else {
          nonAccepting.add(state);
          currentTransitionMap[state] = nonAccepting;
        }
      });
      var all = [
        // 0-equivalent sets.
        [nonAccepting, accepting].filter(function(set3) {
          return set3.size > 0;
        })
      ];
      var current = void 0;
      var previous = void 0;
      current = all[all.length - 1];
      previous = all[all.length - 2];
      var _loop = function _loop2() {
        var newTransitionMap = {};
        var _iteratorNormalCompletion3 = true;
        var _didIteratorError3 = false;
        var _iteratorError3 = void 0;
        try {
          for (var _iterator3 = current[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
            var _set = _step3.value;
            var handledStates = {};
            var _set2 = _toArray(_set), first = _set2[0], rest = _set2.slice(1);
            handledStates[first] = /* @__PURE__ */ new Set([first]);
            var _iteratorNormalCompletion4 = true;
            var _didIteratorError4 = false;
            var _iteratorError4 = void 0;
            try {
              restSets: for (var _iterator4 = rest[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
                var state = _step4.value;
                var _iteratorNormalCompletion5 = true;
                var _didIteratorError5 = false;
                var _iteratorError5 = void 0;
                try {
                  for (var _iterator5 = Object.keys(handledStates)[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
                    var handledState = _step5.value;
                    if (areEquivalent(state, handledState, table, alphabet)) {
                      handledStates[handledState].add(state);
                      handledStates[state] = handledStates[handledState];
                      continue restSets;
                    }
                  }
                } catch (err) {
                  _didIteratorError5 = true;
                  _iteratorError5 = err;
                } finally {
                  try {
                    if (!_iteratorNormalCompletion5 && _iterator5.return) {
                      _iterator5.return();
                    }
                  } finally {
                    if (_didIteratorError5) {
                      throw _iteratorError5;
                    }
                  }
                }
                handledStates[state] = /* @__PURE__ */ new Set([state]);
              }
            } catch (err) {
              _didIteratorError4 = true;
              _iteratorError4 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion4 && _iterator4.return) {
                  _iterator4.return();
                }
              } finally {
                if (_didIteratorError4) {
                  throw _iteratorError4;
                }
              }
            }
            Object.assign(newTransitionMap, handledStates);
          }
        } catch (err) {
          _didIteratorError3 = true;
          _iteratorError3 = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion3 && _iterator3.return) {
              _iterator3.return();
            }
          } finally {
            if (_didIteratorError3) {
              throw _iteratorError3;
            }
          }
        }
        currentTransitionMap = newTransitionMap;
        var newSets = new Set(Object.keys(newTransitionMap).map(function(state2) {
          return newTransitionMap[state2];
        }));
        all.push([].concat(_toConsumableArray(newSets)));
        current = all[all.length - 1];
        previous = all[all.length - 2];
      };
      while (!sameRow(current, previous)) {
        _loop();
      }
      var remaped = /* @__PURE__ */ new Map();
      var idx = 1;
      current.forEach(function(set3) {
        return remaped.set(set3, idx++);
      });
      var minimizedTable = {};
      var minimizedAcceptingStates = /* @__PURE__ */ new Set();
      var updateAcceptingStates = function updateAcceptingStates2(set3, idx2) {
        var _iteratorNormalCompletion = true;
        var _didIteratorError = false;
        var _iteratorError = void 0;
        try {
          for (var _iterator = set3[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
            var state = _step.value;
            if (accepting.has(state)) {
              minimizedAcceptingStates.add(idx2);
            }
          }
        } catch (err) {
          _didIteratorError = true;
          _iteratorError = err;
        } finally {
          try {
            if (!_iteratorNormalCompletion && _iterator.return) {
              _iterator.return();
            }
          } finally {
            if (_didIteratorError) {
              throw _iteratorError;
            }
          }
        }
      };
      var _iteratorNormalCompletion2 = true;
      var _didIteratorError2 = false;
      var _iteratorError2 = void 0;
      try {
        for (var _iterator2 = remaped.entries()[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
          var _ref = _step2.value;
          var _ref2 = _slicedToArray(_ref, 2);
          var set2 = _ref2[0];
          var _idx = _ref2[1];
          minimizedTable[_idx] = {};
          var _iteratorNormalCompletion6 = true;
          var _didIteratorError6 = false;
          var _iteratorError6 = void 0;
          try {
            for (var _iterator6 = alphabet[Symbol.iterator](), _step6; !(_iteratorNormalCompletion6 = (_step6 = _iterator6.next()).done); _iteratorNormalCompletion6 = true) {
              var symbol = _step6.value;
              updateAcceptingStates(set2, _idx);
              var originalTransition = void 0;
              var _iteratorNormalCompletion7 = true;
              var _didIteratorError7 = false;
              var _iteratorError7 = void 0;
              try {
                for (var _iterator7 = set2[Symbol.iterator](), _step7; !(_iteratorNormalCompletion7 = (_step7 = _iterator7.next()).done); _iteratorNormalCompletion7 = true) {
                  var originalState = _step7.value;
                  originalTransition = table[originalState][symbol];
                  if (originalTransition) {
                    break;
                  }
                }
              } catch (err) {
                _didIteratorError7 = true;
                _iteratorError7 = err;
              } finally {
                try {
                  if (!_iteratorNormalCompletion7 && _iterator7.return) {
                    _iterator7.return();
                  }
                } finally {
                  if (_didIteratorError7) {
                    throw _iteratorError7;
                  }
                }
              }
              if (originalTransition) {
                minimizedTable[_idx][symbol] = remaped.get(currentTransitionMap[originalTransition]);
              }
            }
          } catch (err) {
            _didIteratorError6 = true;
            _iteratorError6 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion6 && _iterator6.return) {
                _iterator6.return();
              }
            } finally {
              if (_didIteratorError6) {
                throw _iteratorError6;
              }
            }
          }
        }
      } catch (err) {
        _didIteratorError2 = true;
        _iteratorError2 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion2 && _iterator2.return) {
            _iterator2.return();
          }
        } finally {
          if (_didIteratorError2) {
            throw _iteratorError2;
          }
        }
      }
      dfa.setTransitionTable(minimizedTable);
      dfa.setAcceptingStateNumbers(minimizedAcceptingStates);
      return dfa;
    }
    function sameRow(r1, r2) {
      if (!r2) {
        return false;
      }
      if (r1.length !== r2.length) {
        return false;
      }
      for (var i2 = 0; i2 < r1.length; i2++) {
        var s1 = r1[i2];
        var s2 = r2[i2];
        if (s1.size !== s2.size) {
          return false;
        }
        if ([].concat(_toConsumableArray(s1)).sort().join(",") !== [].concat(_toConsumableArray(s2)).sort().join(",")) {
          return false;
        }
      }
      return true;
    }
    function areEquivalent(s1, s2, table, alphabet) {
      var _iteratorNormalCompletion8 = true;
      var _didIteratorError8 = false;
      var _iteratorError8 = void 0;
      try {
        for (var _iterator8 = alphabet[Symbol.iterator](), _step8; !(_iteratorNormalCompletion8 = (_step8 = _iterator8.next()).done); _iteratorNormalCompletion8 = true) {
          var symbol = _step8.value;
          if (!goToSameSet(s1, s2, table, symbol)) {
            return false;
          }
        }
      } catch (err) {
        _didIteratorError8 = true;
        _iteratorError8 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion8 && _iterator8.return) {
            _iterator8.return();
          }
        } finally {
          if (_didIteratorError8) {
            throw _iteratorError8;
          }
        }
      }
      return true;
    }
    function goToSameSet(s1, s2, table, symbol) {
      if (!currentTransitionMap[s1] || !currentTransitionMap[s2]) {
        return false;
      }
      var originalTransitionS1 = table[s1][symbol];
      var originalTransitionS2 = table[s2][symbol];
      if (!originalTransitionS1 && !originalTransitionS2) {
        return true;
      }
      return currentTransitionMap[s1].has(originalTransitionS1) && currentTransitionMap[s2].has(originalTransitionS2);
    }
    module.exports = {
      minimize
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/dfa/dfa.js
var require_dfa = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/dfa/dfa.js"(exports, module) {
    "use strict";
    var _createClass = /* @__PURE__ */ (function() {
      function defineProperties(target, props) {
        for (var i2 = 0; i2 < props.length; i2++) {
          var descriptor = props[i2];
          descriptor.enumerable = descriptor.enumerable || false;
          descriptor.configurable = true;
          if ("value" in descriptor) descriptor.writable = true;
          Object.defineProperty(target, descriptor.key, descriptor);
        }
      }
      return function(Constructor, protoProps, staticProps) {
        if (protoProps) defineProperties(Constructor.prototype, protoProps);
        if (staticProps) defineProperties(Constructor, staticProps);
        return Constructor;
      };
    })();
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    function _classCallCheck(instance, Constructor) {
      if (!(instance instanceof Constructor)) {
        throw new TypeError("Cannot call a class as a function");
      }
    }
    var DFAMinimizer = require_dfa_minimizer();
    var _require = require_special_symbols();
    var EPSILON_CLOSURE = _require.EPSILON_CLOSURE;
    var DFA = (function() {
      function DFA2(nfa) {
        _classCallCheck(this, DFA2);
        this._nfa = nfa;
      }
      _createClass(DFA2, [{
        key: "minimize",
        value: function minimize() {
          this.getTransitionTable();
          this._originalAcceptingStateNumbers = this._acceptingStateNumbers;
          this._originalTransitionTable = this._transitionTable;
          DFAMinimizer.minimize(this);
        }
        /**
         * Returns alphabet for this DFA.
         */
      }, {
        key: "getAlphabet",
        value: function getAlphabet() {
          return this._nfa.getAlphabet();
        }
        /**
         * Returns accepting states.
         */
      }, {
        key: "getAcceptingStateNumbers",
        value: function getAcceptingStateNumbers() {
          if (!this._acceptingStateNumbers) {
            this.getTransitionTable();
          }
          return this._acceptingStateNumbers;
        }
        /**
         * Returns original accepting states.
         */
      }, {
        key: "getOriginaAcceptingStateNumbers",
        value: function getOriginaAcceptingStateNumbers() {
          if (!this._originalAcceptingStateNumbers) {
            this.getTransitionTable();
          }
          return this._originalAcceptingStateNumbers;
        }
        /**
         * Sets transition table.
         */
      }, {
        key: "setTransitionTable",
        value: function setTransitionTable(table) {
          this._transitionTable = table;
        }
        /**
         * Sets accepting states.
         */
      }, {
        key: "setAcceptingStateNumbers",
        value: function setAcceptingStateNumbers(stateNumbers) {
          this._acceptingStateNumbers = stateNumbers;
        }
        /**
         * DFA transition table is built from NFA table.
         */
      }, {
        key: "getTransitionTable",
        value: function getTransitionTable() {
          var _this = this;
          if (this._transitionTable) {
            return this._transitionTable;
          }
          var nfaTable = this._nfa.getTransitionTable();
          var nfaStates = Object.keys(nfaTable);
          this._acceptingStateNumbers = /* @__PURE__ */ new Set();
          var startState = nfaTable[nfaStates[0]][EPSILON_CLOSURE];
          var worklist = [startState];
          var alphabet = this.getAlphabet();
          var nfaAcceptingStates = this._nfa.getAcceptingStateNumbers();
          var dfaTable = {};
          var updateAcceptingStates = function updateAcceptingStates2(states2) {
            var _iteratorNormalCompletion = true;
            var _didIteratorError = false;
            var _iteratorError = void 0;
            try {
              for (var _iterator = nfaAcceptingStates[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
                var nfaAcceptingState = _step.value;
                if (states2.indexOf(nfaAcceptingState) !== -1) {
                  _this._acceptingStateNumbers.add(states2.join(","));
                  break;
                }
              }
            } catch (err) {
              _didIteratorError = true;
              _iteratorError = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion && _iterator.return) {
                  _iterator.return();
                }
              } finally {
                if (_didIteratorError) {
                  throw _iteratorError;
                }
              }
            }
          };
          while (worklist.length > 0) {
            var states = worklist.shift();
            var dfaStateLabel = states.join(",");
            dfaTable[dfaStateLabel] = {};
            var _iteratorNormalCompletion2 = true;
            var _didIteratorError2 = false;
            var _iteratorError2 = void 0;
            try {
              for (var _iterator2 = alphabet[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
                var symbol = _step2.value;
                var onSymbol = [];
                updateAcceptingStates(states);
                var _iteratorNormalCompletion3 = true;
                var _didIteratorError3 = false;
                var _iteratorError3 = void 0;
                try {
                  for (var _iterator3 = states[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
                    var state = _step3.value;
                    var nfaStatesOnSymbol = nfaTable[state][symbol];
                    if (!nfaStatesOnSymbol) {
                      continue;
                    }
                    var _iteratorNormalCompletion4 = true;
                    var _didIteratorError4 = false;
                    var _iteratorError4 = void 0;
                    try {
                      for (var _iterator4 = nfaStatesOnSymbol[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
                        var nfaStateOnSymbol = _step4.value;
                        if (!nfaTable[nfaStateOnSymbol]) {
                          continue;
                        }
                        onSymbol.push.apply(onSymbol, _toConsumableArray(nfaTable[nfaStateOnSymbol][EPSILON_CLOSURE]));
                      }
                    } catch (err) {
                      _didIteratorError4 = true;
                      _iteratorError4 = err;
                    } finally {
                      try {
                        if (!_iteratorNormalCompletion4 && _iterator4.return) {
                          _iterator4.return();
                        }
                      } finally {
                        if (_didIteratorError4) {
                          throw _iteratorError4;
                        }
                      }
                    }
                  }
                } catch (err) {
                  _didIteratorError3 = true;
                  _iteratorError3 = err;
                } finally {
                  try {
                    if (!_iteratorNormalCompletion3 && _iterator3.return) {
                      _iterator3.return();
                    }
                  } finally {
                    if (_didIteratorError3) {
                      throw _iteratorError3;
                    }
                  }
                }
                var dfaStatesOnSymbolSet = new Set(onSymbol);
                var dfaStatesOnSymbol = [].concat(_toConsumableArray(dfaStatesOnSymbolSet));
                if (dfaStatesOnSymbol.length > 0) {
                  var dfaOnSymbolStr = dfaStatesOnSymbol.join(",");
                  dfaTable[dfaStateLabel][symbol] = dfaOnSymbolStr;
                  if (!dfaTable.hasOwnProperty(dfaOnSymbolStr)) {
                    worklist.unshift(dfaStatesOnSymbol);
                  }
                }
              }
            } catch (err) {
              _didIteratorError2 = true;
              _iteratorError2 = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion2 && _iterator2.return) {
                  _iterator2.return();
                }
              } finally {
                if (_didIteratorError2) {
                  throw _iteratorError2;
                }
              }
            }
          }
          return this._transitionTable = this._remapStateNumbers(dfaTable);
        }
        /**
         * Remaps state numbers in the resulting table:
         * combined states '1,2,3' -> 1, '3,4' -> 2, etc.
         */
      }, {
        key: "_remapStateNumbers",
        value: function _remapStateNumbers(calculatedDFATable) {
          var newStatesMap = {};
          this._originalTransitionTable = calculatedDFATable;
          var transitionTable = {};
          Object.keys(calculatedDFATable).forEach(function(originalNumber2, newNumber) {
            newStatesMap[originalNumber2] = newNumber + 1;
          });
          for (var originalNumber in calculatedDFATable) {
            var originalRow = calculatedDFATable[originalNumber];
            var row = {};
            for (var symbol in originalRow) {
              row[symbol] = newStatesMap[originalRow[symbol]];
            }
            transitionTable[newStatesMap[originalNumber]] = row;
          }
          this._originalAcceptingStateNumbers = this._acceptingStateNumbers;
          this._acceptingStateNumbers = /* @__PURE__ */ new Set();
          var _iteratorNormalCompletion5 = true;
          var _didIteratorError5 = false;
          var _iteratorError5 = void 0;
          try {
            for (var _iterator5 = this._originalAcceptingStateNumbers[Symbol.iterator](), _step5; !(_iteratorNormalCompletion5 = (_step5 = _iterator5.next()).done); _iteratorNormalCompletion5 = true) {
              var _originalNumber = _step5.value;
              this._acceptingStateNumbers.add(newStatesMap[_originalNumber]);
            }
          } catch (err) {
            _didIteratorError5 = true;
            _iteratorError5 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion5 && _iterator5.return) {
                _iterator5.return();
              }
            } finally {
              if (_didIteratorError5) {
                throw _iteratorError5;
              }
            }
          }
          return transitionTable;
        }
        /**
         * Returns original DFA table, where state numbers
         * are combined numbers from NFA.
         */
      }, {
        key: "getOriginalTransitionTable",
        value: function getOriginalTransitionTable() {
          if (!this._originalTransitionTable) {
            this.getTransitionTable();
          }
          return this._originalTransitionTable;
        }
        /**
         * Checks whether this DFA accepts a string.
         */
      }, {
        key: "matches",
        value: function matches(string) {
          var state = 1;
          var i2 = 0;
          var table = this.getTransitionTable();
          while (string[i2]) {
            state = table[state][string[i2++]];
            if (!state) {
              return false;
            }
          }
          if (!this.getAcceptingStateNumbers().has(state)) {
            return false;
          }
          return true;
        }
      }]);
      return DFA2;
    })();
    module.exports = DFA;
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/state.js
var require_state = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/state.js"(exports, module) {
    "use strict";
    var _createClass = /* @__PURE__ */ (function() {
      function defineProperties(target, props) {
        for (var i2 = 0; i2 < props.length; i2++) {
          var descriptor = props[i2];
          descriptor.enumerable = descriptor.enumerable || false;
          descriptor.configurable = true;
          if ("value" in descriptor) descriptor.writable = true;
          Object.defineProperty(target, descriptor.key, descriptor);
        }
      }
      return function(Constructor, protoProps, staticProps) {
        if (protoProps) defineProperties(Constructor.prototype, protoProps);
        if (staticProps) defineProperties(Constructor, staticProps);
        return Constructor;
      };
    })();
    function _classCallCheck(instance, Constructor) {
      if (!(instance instanceof Constructor)) {
        throw new TypeError("Cannot call a class as a function");
      }
    }
    var State2 = (function() {
      function State3() {
        var _ref = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : {}, _ref$accepting = _ref.accepting, accepting = _ref$accepting === void 0 ? false : _ref$accepting;
        _classCallCheck(this, State3);
        this._transitions = /* @__PURE__ */ new Map();
        this.accepting = accepting;
      }
      _createClass(State3, [{
        key: "getTransitions",
        value: function getTransitions() {
          return this._transitions;
        }
        /**
         * Creates a transition on symbol.
         */
      }, {
        key: "addTransition",
        value: function addTransition(symbol, toState) {
          this.getTransitionsOnSymbol(symbol).add(toState);
          return this;
        }
        /**
         * Returns transitions set on symbol.
         */
      }, {
        key: "getTransitionsOnSymbol",
        value: function getTransitionsOnSymbol(symbol) {
          var transitions = this._transitions.get(symbol);
          if (!transitions) {
            transitions = /* @__PURE__ */ new Set();
            this._transitions.set(symbol, transitions);
          }
          return transitions;
        }
      }]);
      return State3;
    })();
    module.exports = State2;
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/nfa/nfa-state.js
var require_nfa_state = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/nfa/nfa-state.js"(exports, module) {
    "use strict";
    var _createClass = /* @__PURE__ */ (function() {
      function defineProperties(target, props) {
        for (var i2 = 0; i2 < props.length; i2++) {
          var descriptor = props[i2];
          descriptor.enumerable = descriptor.enumerable || false;
          descriptor.configurable = true;
          if ("value" in descriptor) descriptor.writable = true;
          Object.defineProperty(target, descriptor.key, descriptor);
        }
      }
      return function(Constructor, protoProps, staticProps) {
        if (protoProps) defineProperties(Constructor.prototype, protoProps);
        if (staticProps) defineProperties(Constructor, staticProps);
        return Constructor;
      };
    })();
    function _classCallCheck(instance, Constructor) {
      if (!(instance instanceof Constructor)) {
        throw new TypeError("Cannot call a class as a function");
      }
    }
    function _possibleConstructorReturn(self, call) {
      if (!self) {
        throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
      }
      return call && (typeof call === "object" || typeof call === "function") ? call : self;
    }
    function _inherits(subClass, superClass) {
      if (typeof superClass !== "function" && superClass !== null) {
        throw new TypeError("Super expression must either be null or a function, not " + typeof superClass);
      }
      subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } });
      if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass;
    }
    var State2 = require_state();
    var _require = require_special_symbols();
    var EPSILON = _require.EPSILON;
    var NFAState = (function(_State) {
      _inherits(NFAState2, _State);
      function NFAState2() {
        _classCallCheck(this, NFAState2);
        return _possibleConstructorReturn(this, (NFAState2.__proto__ || Object.getPrototypeOf(NFAState2)).apply(this, arguments));
      }
      _createClass(NFAState2, [{
        key: "matches",
        /**
         * Whether this state matches a string.
         *
         * We maintain set of visited epsilon-states to avoid infinite loops
         * when an epsilon-transition goes eventually to itself.
         *
         * NOTE: this function is rather "educational", since we use DFA for strings
         * matching. DFA is built on top of NFA, and uses fast transition table.
         */
        value: function matches(string) {
          var visited = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : /* @__PURE__ */ new Set();
          if (visited.has(this)) {
            return false;
          }
          visited.add(this);
          if (string.length === 0) {
            if (this.accepting) {
              return true;
            }
            var _iteratorNormalCompletion = true;
            var _didIteratorError = false;
            var _iteratorError = void 0;
            try {
              for (var _iterator = this.getTransitionsOnSymbol(EPSILON)[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
                var nextState = _step.value;
                if (nextState.matches("", visited)) {
                  return true;
                }
              }
            } catch (err) {
              _didIteratorError = true;
              _iteratorError = err;
            } finally {
              try {
                if (!_iteratorNormalCompletion && _iterator.return) {
                  _iterator.return();
                }
              } finally {
                if (_didIteratorError) {
                  throw _iteratorError;
                }
              }
            }
            return false;
          }
          var symbol = string[0];
          var rest = string.slice(1);
          var symbolTransitions = this.getTransitionsOnSymbol(symbol);
          var _iteratorNormalCompletion2 = true;
          var _didIteratorError2 = false;
          var _iteratorError2 = void 0;
          try {
            for (var _iterator2 = symbolTransitions[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
              var _nextState = _step2.value;
              if (_nextState.matches(rest)) {
                return true;
              }
            }
          } catch (err) {
            _didIteratorError2 = true;
            _iteratorError2 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion2 && _iterator2.return) {
                _iterator2.return();
              }
            } finally {
              if (_didIteratorError2) {
                throw _iteratorError2;
              }
            }
          }
          var _iteratorNormalCompletion3 = true;
          var _didIteratorError3 = false;
          var _iteratorError3 = void 0;
          try {
            for (var _iterator3 = this.getTransitionsOnSymbol(EPSILON)[Symbol.iterator](), _step3; !(_iteratorNormalCompletion3 = (_step3 = _iterator3.next()).done); _iteratorNormalCompletion3 = true) {
              var _nextState2 = _step3.value;
              if (_nextState2.matches(string, visited)) {
                return true;
              }
            }
          } catch (err) {
            _didIteratorError3 = true;
            _iteratorError3 = err;
          } finally {
            try {
              if (!_iteratorNormalCompletion3 && _iterator3.return) {
                _iterator3.return();
              }
            } finally {
              if (_didIteratorError3) {
                throw _iteratorError3;
              }
            }
          }
          return false;
        }
        /**
         * Returns an ε-closure for this state:
         * self + all states following ε-transitions.
         */
      }, {
        key: "getEpsilonClosure",
        value: function getEpsilonClosure() {
          var _this2 = this;
          if (!this._epsilonClosure) {
            (function() {
              var epsilonTransitions = _this2.getTransitionsOnSymbol(EPSILON);
              var closure = _this2._epsilonClosure = /* @__PURE__ */ new Set();
              closure.add(_this2);
              var _iteratorNormalCompletion4 = true;
              var _didIteratorError4 = false;
              var _iteratorError4 = void 0;
              try {
                for (var _iterator4 = epsilonTransitions[Symbol.iterator](), _step4; !(_iteratorNormalCompletion4 = (_step4 = _iterator4.next()).done); _iteratorNormalCompletion4 = true) {
                  var nextState = _step4.value;
                  if (!closure.has(nextState)) {
                    closure.add(nextState);
                    var nextClosure = nextState.getEpsilonClosure();
                    nextClosure.forEach(function(state) {
                      return closure.add(state);
                    });
                  }
                }
              } catch (err) {
                _didIteratorError4 = true;
                _iteratorError4 = err;
              } finally {
                try {
                  if (!_iteratorNormalCompletion4 && _iterator4.return) {
                    _iterator4.return();
                  }
                } finally {
                  if (_didIteratorError4) {
                    throw _iteratorError4;
                  }
                }
              }
            })();
          }
          return this._epsilonClosure;
        }
      }]);
      return NFAState2;
    })(State2);
    module.exports = NFAState;
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/nfa/builders.js
var require_builders = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/nfa/builders.js"(exports, module) {
    "use strict";
    var NFA = require_nfa();
    var NFAState = require_nfa_state();
    var _require = require_special_symbols();
    var EPSILON = _require.EPSILON;
    function char(c) {
      var inState = new NFAState();
      var outState = new NFAState({
        accepting: true
      });
      return new NFA(inState.addTransition(c, outState), outState);
    }
    function e() {
      return char(EPSILON);
    }
    function altPair(first, second) {
      first.out.accepting = false;
      second.out.accepting = true;
      first.out.addTransition(EPSILON, second.in);
      return new NFA(first.in, second.out);
    }
    function alt(first) {
      for (var _len = arguments.length, fragments = Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
        fragments[_key - 1] = arguments[_key];
      }
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = void 0;
      try {
        for (var _iterator = fragments[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var fragment = _step.value;
          first = altPair(first, fragment);
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator.return) {
            _iterator.return();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }
      return first;
    }
    function orPair(first, second) {
      var inState = new NFAState();
      var outState = new NFAState();
      inState.addTransition(EPSILON, first.in);
      inState.addTransition(EPSILON, second.in);
      outState.accepting = true;
      first.out.accepting = false;
      second.out.accepting = false;
      first.out.addTransition(EPSILON, outState);
      second.out.addTransition(EPSILON, outState);
      return new NFA(inState, outState);
    }
    function or(first) {
      for (var _len2 = arguments.length, fragments = Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
        fragments[_key2 - 1] = arguments[_key2];
      }
      var _iteratorNormalCompletion2 = true;
      var _didIteratorError2 = false;
      var _iteratorError2 = void 0;
      try {
        for (var _iterator2 = fragments[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
          var fragment = _step2.value;
          first = orPair(first, fragment);
        }
      } catch (err) {
        _didIteratorError2 = true;
        _iteratorError2 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion2 && _iterator2.return) {
            _iterator2.return();
          }
        } finally {
          if (_didIteratorError2) {
            throw _iteratorError2;
          }
        }
      }
      return first;
    }
    function repExplicit(fragment) {
      var inState = new NFAState();
      var outState = new NFAState({
        accepting: true
      });
      inState.addTransition(EPSILON, fragment.in);
      inState.addTransition(EPSILON, outState);
      fragment.out.accepting = false;
      fragment.out.addTransition(EPSILON, outState);
      outState.addTransition(EPSILON, fragment.in);
      return new NFA(inState, outState);
    }
    function rep(fragment) {
      fragment.in.addTransition(EPSILON, fragment.out);
      fragment.out.addTransition(EPSILON, fragment.in);
      return fragment;
    }
    function plusRep(fragment) {
      fragment.out.addTransition(EPSILON, fragment.in);
      return fragment;
    }
    function questionRep(fragment) {
      fragment.in.addTransition(EPSILON, fragment.out);
      return fragment;
    }
    module.exports = {
      alt,
      char,
      e,
      or,
      rep,
      repExplicit,
      plusRep,
      questionRep
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/nfa/nfa-from-regexp.js
var require_nfa_from_regexp = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/nfa/nfa-from-regexp.js"(exports, module) {
    "use strict";
    function _toConsumableArray(arr) {
      if (Array.isArray(arr)) {
        for (var i2 = 0, arr2 = Array(arr.length); i2 < arr.length; i2++) {
          arr2[i2] = arr[i2];
        }
        return arr2;
      } else {
        return Array.from(arr);
      }
    }
    var parser = require_parser();
    var _require = require_builders();
    var alt = _require.alt;
    var char = _require.char;
    var or = _require.or;
    var rep = _require.rep;
    var plusRep = _require.plusRep;
    var questionRep = _require.questionRep;
    function gen(node) {
      if (node && !generator[node.type]) {
        throw new Error(node.type + " is not supported in NFA/DFA interpreter.");
      }
      return node ? generator[node.type](node) : "";
    }
    var generator = {
      RegExp: function RegExp2(node) {
        if (node.flags !== "") {
          throw new Error("NFA/DFA: Flags are not supported yet.");
        }
        return gen(node.body);
      },
      Alternative: function Alternative(node) {
        var fragments = (node.expressions || []).map(gen);
        return alt.apply(void 0, _toConsumableArray(fragments));
      },
      Disjunction: function Disjunction(node) {
        return or(gen(node.left), gen(node.right));
      },
      Repetition: function Repetition(node) {
        switch (node.quantifier.kind) {
          case "*":
            return rep(gen(node.expression));
          case "+":
            return plusRep(gen(node.expression));
          case "?":
            return questionRep(gen(node.expression));
          default:
            throw new Error("Unknown repeatition: " + node.quantifier.kind + ".");
        }
      },
      Char: function Char(node) {
        if (node.kind !== "simple") {
          throw new Error("NFA/DFA: Only simple chars are supported yet.");
        }
        return char(node.value);
      },
      Group: function Group(node) {
        return gen(node.expression);
      }
    };
    module.exports = {
      /**
       * Builds an NFA from the passed regexp.
       */
      build: function build(regexp) {
        var ast = regexp;
        if (regexp instanceof RegExp) {
          regexp = "" + regexp;
        }
        if (typeof regexp === "string") {
          ast = parser.parse(regexp, {
            captureLocations: true
          });
        }
        return gen(ast);
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/index.js
var require_finite_automaton = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/interpreter/finite-automaton/index.js"(exports, module) {
    "use strict";
    var NFA = require_nfa();
    var DFA = require_dfa();
    var nfaFromRegExp = require_nfa_from_regexp();
    var builders = require_builders();
    module.exports = {
      /**
       * Export NFA and DFA classes.
       */
      NFA,
      DFA,
      /**
       * Expose builders.
       */
      builders,
      /**
       * Builds an NFA for the passed regexp.
       *
       * @param string | AST | RegExp:
       *
       *   a regular expression in different representations: a string,
       *   a RegExp object, or an AST.
       */
      toNFA: function toNFA(regexp) {
        return nfaFromRegExp.build(regexp);
      },
      /**
       * Builds DFA for the passed regexp.
       *
       * @param string | AST | RegExp:
       *
       *   a regular expression in different representations: a string,
       *   a RegExp object, or an AST.
       */
      toDFA: function toDFA(regexp) {
        return new DFA(this.toNFA(regexp));
      },
      /**
       * Returns true if regexp accepts the string.
       */
      test: function test(regexp, string) {
        return this.toDFA(regexp).matches(string);
      }
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/runtime/index.js
var require_runtime = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/compat-transpiler/runtime/index.js"(exports, module) {
    "use strict";
    var _createClass = /* @__PURE__ */ (function() {
      function defineProperties(target, props) {
        for (var i2 = 0; i2 < props.length; i2++) {
          var descriptor = props[i2];
          descriptor.enumerable = descriptor.enumerable || false;
          descriptor.configurable = true;
          if ("value" in descriptor) descriptor.writable = true;
          Object.defineProperty(target, descriptor.key, descriptor);
        }
      }
      return function(Constructor, protoProps, staticProps) {
        if (protoProps) defineProperties(Constructor.prototype, protoProps);
        if (staticProps) defineProperties(Constructor, staticProps);
        return Constructor;
      };
    })();
    function _classCallCheck(instance, Constructor) {
      if (!(instance instanceof Constructor)) {
        throw new TypeError("Cannot call a class as a function");
      }
    }
    var RegExpTree = (function() {
      function RegExpTree2(re, _ref) {
        var flags = _ref.flags, groups = _ref.groups, source = _ref.source;
        _classCallCheck(this, RegExpTree2);
        this._re = re;
        this._groups = groups;
        this.flags = flags;
        this.source = source || re.source;
        this.dotAll = flags.includes("s");
        this.global = re.global;
        this.ignoreCase = re.ignoreCase;
        this.multiline = re.multiline;
        this.sticky = re.sticky;
        this.unicode = re.unicode;
      }
      _createClass(RegExpTree2, [{
        key: "test",
        value: function test(string) {
          return this._re.test(string);
        }
        /**
         * Facade wrapper for RegExp `compile` method.
         */
      }, {
        key: "compile",
        value: function compile(string) {
          return this._re.compile(string);
        }
        /**
         * Facade wrapper for RegExp `toString` method.
         */
      }, {
        key: "toString",
        value: function toString2() {
          if (!this._toStringResult) {
            this._toStringResult = "/" + this.source + "/" + this.flags;
          }
          return this._toStringResult;
        }
        /**
         * Facade wrapper for RegExp `exec` method.
         */
      }, {
        key: "exec",
        value: function exec(string) {
          var result = this._re.exec(string);
          if (!this._groups || !result) {
            return result;
          }
          result.groups = {};
          for (var group in this._groups) {
            var groupNumber = this._groups[group];
            result.groups[group] = result[groupNumber];
          }
          return result;
        }
      }]);
      return RegExpTree2;
    })();
    module.exports = {
      RegExpTree
    };
  }
});

// scratch/lcm-build/node_modules/regexp-tree/dist/regexp-tree.js
var require_regexp_tree2 = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/dist/regexp-tree.js"(exports, module) {
    "use strict";
    var compatTranspiler = require_compat_transpiler();
    var generator = require_generator();
    var optimizer = require_optimizer();
    var parser = require_parser();
    var _transform = require_transform();
    var _traverse = require_traverse();
    var fa = require_finite_automaton();
    var _require = require_runtime();
    var RegExpTree = _require.RegExpTree;
    var regexpTree2 = {
      /**
       * Parser module exposed.
       */
      parser,
      /**
       * Expose finite-automaton module.
       */
      fa,
      /**
       * `TransformResult` exposed.
       */
      TransformResult: _transform.TransformResult,
      /**
       * Parses a regexp string, producing an AST.
       *
       * @param string regexp
       *
       *   a regular expression in different formats: string, AST, RegExp.
       *
       * @param Object options
       *
       *   parsing options for this parse call. Default are:
       *
       *     - captureLocations: boolean
       *     - any other custom options
       *
       * @return Object AST
       */
      parse: function parse(regexp, options) {
        return parser.parse("" + regexp, options);
      },
      /**
       * Traverses a RegExp AST.
       *
       * @param Object ast
       * @param Object | Array<Object> handlers
       *
       * Each `handler` is an object containing handler function for needed
       * node types. Example:
       *
       *   regexpTree.traverse(ast, {
       *     onChar(node) {
       *       ...
       *     },
       *   });
       *
       * The value for a node type may also be an object with functions pre and post.
       * This enables more context-aware analyses, e.g. measuring star height.
       */
      traverse: function traverse(ast, handlers, options) {
        return _traverse.traverse(ast, handlers, options);
      },
      /**
       * Transforms a regular expression.
       *
       * A regexp can be passed in different formats (string, regexp or AST),
       * applying a set of transformations. It is a convenient wrapper
       * on top of "parse-traverse-generate" tool chain.
       *
       * @param string | AST | RegExp regexp - a regular expression;
       * @param Object | Array<Object> handlers - a list of handlers.
       *
       * @return TransformResult - a transformation result.
       */
      transform: function transform(regexp, handlers) {
        return _transform.transform(regexp, handlers);
      },
      /**
       * Generates a RegExp string from an AST.
       *
       * @param Object ast
       *
       * Invariant:
       *
       *   regexpTree.generate(regexpTree.parse('/[a-z]+/i')); // '/[a-z]+/i'
       */
      generate: function generate(ast) {
        return generator.generate(ast);
      },
      /**
       * Creates a RegExp object from a regexp string.
       *
       * @param string regexp
       */
      toRegExp: function toRegExp(regexp) {
        var compat = this.compatTranspile(regexp);
        return new RegExp(compat.getSource(), compat.getFlags());
      },
      /**
       * Optimizes a regular expression by replacing some
       * sub-expressions with their idiomatic patterns.
       *
       * @param string regexp
       *
       * @return TransformResult object
       */
      optimize: function optimize(regexp, whitelist) {
        var _ref = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : {}, blacklist = _ref.blacklist;
        return optimizer.optimize(regexp, { whitelist, blacklist });
      },
      /**
       * Translates a regular expression in new syntax or in new format
       * into equivalent expressions in old syntax.
       *
       * @param string regexp
       *
       * @return TransformResult object
       */
      compatTranspile: function compatTranspile(regexp, whitelist) {
        return compatTranspiler.transform(regexp, whitelist);
      },
      /**
       * Executes a regular expression on a string.
       *
       * @param RegExp|string re - a regular expression.
       * @param string string - a testing string.
       */
      exec: function exec(re, string) {
        if (typeof re === "string") {
          var compat = this.compatTranspile(re);
          var extra = compat.getExtra();
          if (extra.namedCapturingGroups) {
            re = new RegExpTree(compat.toRegExp(), {
              flags: compat.getFlags(),
              source: compat.getSource(),
              groups: extra.namedCapturingGroups
            });
          } else {
            re = compat.toRegExp();
          }
        }
        return re.exec(string);
      }
    };
    module.exports = regexpTree2;
  }
});

// scratch/lcm-build/node_modules/regexp-tree/index.js
var require_regexp_tree3 = __commonJS({
  "scratch/lcm-build/node_modules/regexp-tree/index.js"(exports, module) {
    "use strict";
    module.exports = require_regexp_tree2();
  }
});

// scratch/lcm-build/node_modules/safe-regex/lib/heuristic-analyzer.js
var require_heuristic_analyzer = __commonJS({
  "scratch/lcm-build/node_modules/safe-regex/lib/heuristic-analyzer.js"(exports, module) {
    var regexpTree2 = require_regexp_tree3();
    var analyzer = require_analyzer();
    var HeuristicAnalyzer = class extends analyzer.Analyzer {
      constructor(analyzerOptions) {
        super(analyzerOptions);
      }
      isVulnerable(regExp) {
        const starHeight = this._measureStarHeight(regExp);
        if (starHeight > 1) {
          return true;
        }
        const nRepetitions = this._measureRepetitions(regExp);
        if (nRepetitions > this.options.heuristic_replimit) {
          return true;
        }
        return false;
      }
      genAttackString(regExp) {
        return null;
      }
      _measureStarHeight(regExp) {
        let currentStarHeight = 0;
        let maxObservedStarHeight = 0;
        const ast = regexpTree2.parse(regExp);
        regexpTree2.traverse(ast, {
          Repetition: {
            pre({ node }) {
              currentStarHeight++;
              if (maxObservedStarHeight < currentStarHeight) {
                maxObservedStarHeight = currentStarHeight;
              }
            },
            post({ node }) {
              currentStarHeight--;
            }
          }
        });
        return maxObservedStarHeight;
      }
      _measureRepetitions(regExp) {
        let nRepetitions = 0;
        const ast = regexpTree2.parse(regExp);
        regexpTree2.traverse(ast, {
          Repetition: {
            pre({ node }) {
              nRepetitions++;
            }
          }
        });
        return nRepetitions;
      }
    };
    module.exports = HeuristicAnalyzer;
  }
});

// scratch/lcm-build/node_modules/safe-regex/lib/analyzer-family.js
var require_analyzer_family = __commonJS({
  "scratch/lcm-build/node_modules/safe-regex/lib/analyzer-family.js"(exports, module) {
    var heuristicAnalyzer = require_heuristic_analyzer();
    module.exports = [heuristicAnalyzer];
  }
});

// scratch/lcm-build/node_modules/safe-regex/index.js
var require_safe_regex = __commonJS({
  "scratch/lcm-build/node_modules/safe-regex/index.js"(exports, module) {
    var analyzer = require_analyzer();
    var analyzerFamily = require_analyzer_family();
    var DEFAULT_SAFE_REP_LIMIT = 25;
    var RET_IS_SAFE = true;
    var RET_IS_VULNERABLE = false;
    var Args = class {
      constructor(regExp, analyzerOptions) {
        this.regExp = regExp;
        this.analyzerOptions = analyzerOptions;
      }
    };
    function safeRegex2(re, opts) {
      try {
        const args = buildArgs(re, opts);
        const analyzerResponses = askAnalyzersIfVulnerable(args);
        if (analyzerResponses.find((isVulnerable) => isVulnerable)) {
          return RET_IS_VULNERABLE;
        } else {
          return RET_IS_SAFE;
        }
      } catch (err) {
        return false;
      }
    }
    function buildArgs(re, opts) {
      if (!opts) opts = {};
      const heuristic_replimit = opts.limit === void 0 ? DEFAULT_SAFE_REP_LIMIT : opts.limit;
      const analyzerOptions = new analyzer.AnalyzerOptions(heuristic_replimit);
      let regExp = null;
      if (re instanceof RegExp) {
        regExp = re;
      } else if (typeof re === "string") {
        regExp = new RegExp(re);
      } else {
        regExp = new RegExp(String(re));
      }
      return new Args(regExp, analyzerOptions);
    }
    function askAnalyzersIfVulnerable(args) {
      let analyzerSaysVulnerable = [];
      let Analyzer;
      for (Analyzer of analyzerFamily) {
        try {
          const analyzer2 = new Analyzer(args.analyzerOptions);
          analyzerSaysVulnerable.push(analyzer2.isVulnerable(args.regExp));
        } catch (err) {
          analyzerSaysVulnerable.push(false);
        }
      }
      return analyzerSaysVulnerable;
    }
    module.exports = safeRegex2;
  }
});

// ../_research/lcm-full-20261021/src/store/summary-lineage.ts
var SUMMARY_SOURCE_IDS_SQL = `
  WITH RECURSIVE source_ids(summary_id) AS (
    SELECT summary_id FROM summaries WHERE summary_id = ?
    UNION
    SELECT sp.parent_summary_id FROM summary_parents sp
    JOIN source_ids ON sp.summary_id = source_ids.summary_id
  )
  SELECT summary_id FROM source_ids`;

// ../_research/lcm-full-20261021/src/db/project-timeline.ts
var TIMELINE_SESSION_ID = "lcm:project-timeline";
function installProjectTimeline(db) {
  db.exec("DROP TRIGGER IF EXISTS timeline_replay_complete");
  installTimelineTables(db);
  const tracking = db.prepare("SELECT tracking FROM timeline_state WHERE id = 1").get();
  if (tracking.tracking) installTimelineTriggers(db);
  else dropTimelineTriggers(db);
  archiveTimelinePromotions(db);
}
function installTimelineTables(db) {
  const columns = db.prepare("PRAGMA table_info(conversations)").all();
  if (!columns.some((column) => column.name === "is_timeline")) {
    db.exec("ALTER TABLE conversations ADD COLUMN is_timeline INTEGER NOT NULL DEFAULT 0 CHECK (is_timeline IN (0, 1))");
  }
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS timeline_owner_idx ON conversations(is_timeline) WHERE is_timeline = 1;
    CREATE UNIQUE INDEX IF NOT EXISTS timeline_session_idx ON conversations(session_id) WHERE session_id = 'lcm:project-timeline';
    CREATE TABLE IF NOT EXISTS timeline_nodes (
      summary_id TEXT PRIMARY KEY REFERENCES summaries(summary_id) ON DELETE CASCADE,
      work_key TEXT NOT NULL,
      level TEXT NOT NULL DEFAULT 'period' CHECK(level IN ('digest', 'period')),
      period_from TEXT NOT NULL,
      period_to TEXT NOT NULL,
      generator TEXT NOT NULL,
      replaces TEXT NOT NULL DEFAULT '[]',
      active INTEGER NOT NULL DEFAULT 1,
      stale_reason TEXT,
      stale_since TEXT
    );
    CREATE INDEX IF NOT EXISTS timeline_work_idx ON timeline_nodes(work_key, active);
    CREATE TABLE IF NOT EXISTS timeline_sources (
      summary_id TEXT NOT NULL REFERENCES timeline_nodes(summary_id) ON DELETE CASCADE,
      conversation_id INTEGER NOT NULL,
      session_id TEXT NOT NULL,
      revision TEXT NOT NULL,
      summary_ids TEXT NOT NULL,
      message_ids TEXT NOT NULL,
      message_range TEXT,
      PRIMARY KEY(summary_id, conversation_id)
    );
    CREATE INDEX IF NOT EXISTS timeline_source_idx ON timeline_sources(conversation_id);
    CREATE TABLE IF NOT EXISTS timeline_memory_refs (
      summary_id TEXT NOT NULL REFERENCES timeline_nodes(summary_id) ON DELETE CASCADE,
      memory_id TEXT NOT NULL,
      revision TEXT NOT NULL,
      PRIMARY KEY(summary_id, memory_id)
    );
    CREATE INDEX IF NOT EXISTS timeline_memory_idx ON timeline_memory_refs(memory_id);
    CREATE TABLE IF NOT EXISTS timeline_state (
      id INTEGER PRIMARY KEY CHECK(id = 1), tracking INTEGER NOT NULL DEFAULT 0,
      generation INTEGER NOT NULL DEFAULT 0, phase TEXT NOT NULL DEFAULT 'off',
      bootstrap_cursor TEXT NOT NULL DEFAULT '', reconcile_cursor INTEGER NOT NULL DEFAULT 0,
      generator TEXT, published INTEGER NOT NULL DEFAULT 0, admission_recovered INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS timeline_dirty (
      session_id TEXT PRIMARY KEY, rev INTEGER NOT NULL DEFAULT 0, dirty INTEGER NOT NULL DEFAULT 1,
      reason TEXT NOT NULL DEFAULT 'session-changed', bumped_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
    CREATE INDEX IF NOT EXISTS timeline_dirty_ready_idx ON timeline_dirty(dirty, session_id);
    CREATE TABLE IF NOT EXISTS timeline_sessions (session_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS timeline_items (
      item_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, conversation_id INTEGER NOT NULL,
      month TEXT NOT NULL, metadata TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS timeline_item_session_idx ON timeline_items(session_id);
    CREATE INDEX IF NOT EXISTS timeline_item_month_idx ON timeline_items(month);
    CREATE TABLE IF NOT EXISTS timeline_units (
      work_key TEXT PRIMARY KEY, level TEXT NOT NULL, month TEXT NOT NULL, metadata TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'ready', failures INTEGER NOT NULL DEFAULT 0, next_try TEXT,
      period_to TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS timeline_unit_month_idx ON timeline_units(month);
    CREATE INDEX IF NOT EXISTS timeline_unit_ready_idx ON timeline_units(status, period_to);
    CREATE TABLE IF NOT EXISTS timeline_months (month TEXT PRIMARY KEY, replan INTEGER NOT NULL DEFAULT 1);
    CREATE INDEX IF NOT EXISTS timeline_month_replan_idx ON timeline_months(replan);
    CREATE TABLE IF NOT EXISTS timeline_memory_dirty (memory_id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS timeline_reconcile (conversation_id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, fingerprint TEXT NOT NULL);
    DROP TABLE IF EXISTS timeline_input_cache_batches;
    DROP TABLE IF EXISTS timeline_input_cache;
    DROP TABLE IF EXISTS timeline_journal;
    DROP TABLE IF EXISTS timeline_checkpoint;
    CREATE INDEX IF NOT EXISTS timeline_source_session_idx ON timeline_sources(session_id);
    CREATE INDEX IF NOT EXISTS timeline_active_idx ON timeline_nodes(active, stale_reason);
    CREATE INDEX IF NOT EXISTS timeline_replay_session_idx ON replay_manifest(session_id, run_id);
  `);
  if (!db.prepare("SELECT 1 FROM timeline_state WHERE id = 1").get()) {
    db.exec("INSERT OR IGNORE INTO timeline_state(id) VALUES (1)");
  }
  const sourceColumns = db.prepare("PRAGMA table_info(timeline_sources)").all();
  if (!sourceColumns.some((column) => column.name === "time_basis")) {
    db.exec("ALTER TABLE timeline_sources ADD COLUMN time_basis TEXT NOT NULL DEFAULT 'capture'");
    db.exec("UPDATE timeline_state SET phase = 'bootstrapping', bootstrap_cursor = '' WHERE tracking = 1");
  }
  const stateColumns = db.prepare("PRAGMA table_info(timeline_state)").all();
  if (!stateColumns.some((column) => column.name === "known_time_bounds")) {
    db.exec("ALTER TABLE timeline_state ADD COLUMN known_time_bounds INTEGER NOT NULL DEFAULT 1");
    db.exec("UPDATE timeline_state SET phase = 'bootstrapping', bootstrap_cursor = '' WHERE tracking = 1");
  }
  if (!stateColumns.some((column) => column.name === "admission_recovered")) {
    db.exec("ALTER TABLE timeline_state ADD COLUMN admission_recovered INTEGER NOT NULL DEFAULT 0");
  }
  if (stateColumns.some((column) => column.name === "drain")) {
    db.exec("ALTER TABLE timeline_state DROP COLUMN drain");
  }
}
function installTimelineTriggers(db) {
  for (const table of ["context_items"]) for (const operation of ["insert", "update", "delete"]) {
    for (const row of ["new", "old"]) db.exec(`DROP TRIGGER IF EXISTS timeline_${table}_${operation}_${row}`);
  }
  db.exec("DROP TRIGGER IF EXISTS timeline_conversations_update_old");
  for (const [name, sql] of timelineTriggerSql()) {
    const prior = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?").get(name);
    if (prior && normalizedTriggerSql(prior.sql) === normalizedTriggerSql(sql)) continue;
    db.exec(`DROP TRIGGER IF EXISTS ${name}`);
    db.exec(sql);
  }
}
function normalizedTriggerSql(value) {
  return value.replace(/\s+/g, " ").trim();
}
function timelineTriggerSql() {
  const triggers = /* @__PURE__ */ new Map();
  const install = (name, body) => {
    triggers.set(name, `CREATE TRIGGER ${name} ${body}`);
  };
  const bump = (session, reason = "session-changed") => `
    INSERT INTO timeline_dirty(session_id, rev, dirty, reason, bumped_at) VALUES (${session}, 1, 1, '${reason}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(session_id) DO UPDATE SET rev = rev + 1, dirty = 1, reason = '${reason}', bumped_at = excluded.bumped_at;`;
  const flagSession = (conversation, reason = "session-changed", detach = false) => `
    ${bump(`(SELECT session_id FROM conversations WHERE conversation_id = ${conversation})`, reason)}
    ${detach ? `UPDATE timeline_nodes SET stale_reason = COALESCE(stale_reason, '${reason}'),
      stale_since = COALESCE(stale_since, datetime('now'))
      WHERE summary_id IN (SELECT summary_id FROM timeline_sources WHERE conversation_id = ${conversation});` : ""}`;
  const sessionTrigger = ({ table, operation, row, conversation, before = false, extra = "", condition = "1" }) => {
    install(`timeline_${table}_${operation}_${row.toLowerCase()}`, `
      ${before ? "BEFORE" : "AFTER"} ${operation.toUpperCase()} ON ${table}
      WHEN (${condition}) AND EXISTS (SELECT 1 FROM conversations WHERE conversation_id = ${conversation} AND is_timeline = 0)
      BEGIN
        ${flagSession(conversation, table === "conversations" && operation === "delete" ? "session-removed" : "session-changed", operation === "delete")}
        ${extra}
      END`);
  };
  for (const table of ["messages", "summaries", "conversations"]) {
    for (const operation of ["insert", "update", "delete"]) {
      const row = operation === "delete" ? "OLD" : "NEW";
      const conversation = `${row}.conversation_id`;
      const extra = table === "summaries" && operation === "delete" ? "DELETE FROM summary_parents WHERE parent_summary_id = OLD.summary_id AND summary_id IN (SELECT summary_id FROM timeline_nodes);" : table === "messages" && operation === "delete" ? "DELETE FROM summary_messages WHERE message_id = OLD.message_id AND summary_id IN (SELECT summary_id FROM timeline_nodes);" : table === "conversations" && operation === "delete" ? `DELETE FROM summary_parents WHERE parent_summary_id IN
                 (SELECT summary_id FROM summaries WHERE conversation_id = OLD.conversation_id)
                 AND summary_id IN (SELECT summary_id FROM timeline_nodes);
               DELETE FROM summary_messages WHERE message_id IN
                 (SELECT message_id FROM messages WHERE conversation_id = OLD.conversation_id)
                 AND summary_id IN (SELECT summary_id FROM timeline_nodes);` : "";
      sessionTrigger({ table, operation, row, conversation, before: operation === "delete", extra });
      if (operation === "update" && table !== "conversations") sessionTrigger({ table, operation, row: "OLD", conversation: "OLD.conversation_id", condition: "OLD.conversation_id IS NOT NEW.conversation_id" });
      if (operation === "update" && table === "conversations") install("timeline_conversations_rename", `AFTER UPDATE ON conversations
        WHEN OLD.is_timeline = 0 AND OLD.session_id IS NOT NEW.session_id BEGIN ${bump("OLD.session_id", "session-removed")} END`);
    }
  }
  for (const table of ["summary_parents", "summary_messages", "message_parts"]) {
    for (const operation of ["insert", "update", "delete"]) {
      for (const row of operation === "update" ? ["NEW", "OLD"] : [operation === "delete" ? "OLD" : "NEW"]) {
        const conversation = table === "message_parts" ? `(SELECT conversation_id FROM messages WHERE message_id = ${row}.message_id)` : `(SELECT conversation_id FROM summaries WHERE summary_id = ${row}.summary_id)`;
        let condition = table === "message_parts" ? operation === "update" ? "(OLD.part_type = 'compaction' OR NEW.part_type = 'compaction') AND (OLD.part_type IS NOT NEW.part_type OR OLD.message_id IS NOT NEW.message_id)" : `${row}.part_type = 'compaction'` : "1";
        if (operation === "update" && row === "OLD") {
          const ownerKey = table === "message_parts" ? "message_id" : "summary_id";
          condition += ` AND OLD.${ownerKey} IS NOT NEW.${ownerKey}`;
        }
        sessionTrigger({ table, operation, row, conversation, before: operation === "delete", condition });
      }
    }
  }
  for (const operation of ["insert", "update", "delete"]) {
    const row = operation === "delete" ? "OLD" : "NEW";
    install(`timeline_promoted_${operation}`, `AFTER ${operation.toUpperCase()} ON promoted
      WHEN 1
      ${operation === "update" ? `AND (OLD.content IS NOT NEW.content OR OLD.tags IS NOT NEW.tags
        OR OLD.archived_at IS NOT NEW.archived_at)` : ""}
      BEGIN
        INSERT OR IGNORE INTO timeline_memory_dirty VALUES (${row}.id);
        UPDATE timeline_nodes SET stale_reason = COALESCE(stale_reason, 'memory-changed'),
          stale_since = COALESCE(stale_since, datetime('now'))
          WHERE summary_id IN (SELECT summary_id FROM timeline_memory_refs WHERE memory_id = ${row}.id);
      END`);
  }
  for (const operation of ["insert", "update", "delete"]) {
    const row = operation === "delete" ? "OLD" : "NEW";
    install(`timeline_replay_${operation}`, `AFTER ${operation.toUpperCase()} ON replay_manifest
      WHEN 1
      BEGIN
        ${bump(`${row}.session_id`)}
      END`);
  }
  return triggers;
}
function dropTimelineTriggers(db) {
  const rows = db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'timeline_%'").all();
  for (const row of rows) db.exec(`DROP TRIGGER "${row.name.replaceAll('"', '""')}"`);
}
function indexTimelinePromotionLookups(db) {
  for (const [name, column] of [["promoted_session_idx", "session_id"], ["promoted_source_summary_idx", "source_summary_id"]]) {
    const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?").get(name);
    if (!exists) db.exec(`CREATE INDEX ${name} ON promoted(${column})`);
  }
}
function archiveTimelinePromotions(db) {
  if (!db.prepare("SELECT 1 FROM conversations WHERE is_timeline = 1").get()) return;
  indexTimelinePromotionLookups(db);
  const rows = db.prepare(`SELECT p.id, p.rowid FROM promoted p WHERE p.archived_at IS NULL
    AND (p.session_id = ? OR p.source_summary_id IN (
      SELECT s.summary_id FROM summaries s JOIN conversations c USING(conversation_id) WHERE c.is_timeline = 1))`).all(TIMELINE_SESSION_ID);
  if (!rows.length) return;
  const hasFts = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'promoted_fts'").get();
  db.exec("SAVEPOINT timeline_archive_promoted");
  try {
    for (const row of rows) {
      db.prepare("UPDATE promoted SET archived_at = datetime('now') WHERE id = ? AND archived_at IS NULL").run(row.id);
      if (hasFts) db.prepare("DELETE FROM promoted_fts WHERE rowid = ?").run(row.rowid);
    }
    db.exec("RELEASE timeline_archive_promoted");
  } catch (error) {
    db.exec("ROLLBACK TO timeline_archive_promoted");
    db.exec("RELEASE timeline_archive_promoted");
    throw error;
  }
}

// ../_research/lcm-full-20261021/src/store/worker-store.ts
import { realpathSync } from "node:fs";

// ../_research/lcm-full-20261021/src/claude-rebuild.ts
import * as sqlite from "node:sqlite";

// ../_research/lcm-full-20261021/src/scrub.ts
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
var _thisDir = dirname(fileURLToPath(import.meta.url));

// ../_research/lcm-full-20261021/src/tool-calls.ts
var SHELL_TOOLS = ["bash", "exec_command", "shell", "shell_command"];

// ../_research/lcm-full-20261021/src/transcript.ts
var COMMAND_NAME_RE = /<command-name>([^<]*)<\/command-name>/;
var COMMAND_ARGS_RE = /<command-args>([^<]*)<\/command-args>/;
function stripCodeFences(text) {
  return text.replace(/```[\s\S]*?```/g, "");
}
function extractCommandParts(text) {
  const searchable = stripCodeFences(text);
  const name = searchable.match(COMMAND_NAME_RE)?.[1]?.trim();
  if (!name) return [];
  const args = searchable.match(COMMAND_ARGS_RE)?.[1]?.trim() ?? "";
  return [{ type: "command", name, args: args || null }];
}

// ../_research/lcm-full-20261021/src/claude-rebuild.ts
function clearConversationForRebuild(db, conversationId, sessionId) {
  const summaryIds = "SELECT summary_id FROM summaries WHERE conversation_id = ?";
  const hasTable = (name) => db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) !== void 0;
  if (hasTable("summaries_fts")) db.prepare(`DELETE FROM summaries_fts WHERE summary_id IN (${summaryIds})`).run(conversationId);
  if (hasTable("messages_fts")) {
    db.prepare("DELETE FROM messages_fts WHERE rowid IN (SELECT message_id FROM messages WHERE conversation_id = ?)").run(conversationId);
  }
  db.prepare("DELETE FROM context_items WHERE conversation_id = ?").run(conversationId);
  db.prepare(`DELETE FROM summary_messages WHERE summary_id IN (${summaryIds})`).run(conversationId);
  db.prepare(`DELETE FROM summary_parents WHERE summary_id IN (${summaryIds})`).run(conversationId);
  db.prepare("DELETE FROM summaries WHERE conversation_id = ?").run(conversationId);
  db.prepare("DELETE FROM messages WHERE conversation_id = ?").run(conversationId);
  db.prepare("DELETE FROM replay_ledger WHERE session_id = ?").run(sessionId);
}

// ../_research/lcm-full-20261021/src/store/worker-store.ts
var ISSUED_JOB_RETENTION_DAYS = 90;
var WorkerStore = class {
  constructor(db) {
    this.db = db;
  }
  db;
  list() {
    if (!this.db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'summarize_workers'").get()) return [];
    return this.db.prepare(`SELECT session_id, cwd, client, owner, state, last_activity, ${this.reasonColumn()}
      FROM summarize_workers ORDER BY session_id`).all();
  }
  get(sessionId) {
    if (!this.db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'summarize_workers'").get()) return void 0;
    return this.db.prepare(`SELECT session_id, cwd, client, owner, state, last_activity, ${this.reasonColumn()}
      FROM summarize_workers WHERE session_id = ?`).get(sessionId);
  }
  /** Diagnostic reads also support a database not yet migrated by this version. */
  reasonColumn() {
    const columns = this.db.prepare("PRAGMA table_info(summarize_workers)").all();
    return columns.some((column) => column.name === "exclusion_reason") ? "exclusion_reason" : "NULL AS exclusion_reason";
  }
  excluded(sessionId, parentSessionId) {
    if (!this.db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'summarize_workers'").get()) return false;
    const row = this.db.prepare(`WITH RECURSIVE ancestors(id) AS (
      SELECT ? UNION SELECT parent_session_id FROM conversations JOIN ancestors ON session_id = ancestors.id
      WHERE parent_session_id IS NOT NULL
    ) SELECT 1 FROM summarize_workers JOIN ancestors ON session_id = ancestors.id LIMIT 1`).get(sessionId);
    return Boolean(row || parentSessionId && this.excluded(parentSessionId));
  }
  live(sessionId, cwd, client) {
    try {
      cwd = realpathSync(cwd);
    } catch {
    }
    return Boolean(this.db.prepare(`SELECT 1 FROM summarize_workers
      WHERE session_id = ? AND cwd = ? AND client = ? AND state IN ('active', 'abandoned') AND owner IS NOT NULL`).get(sessionId, cwd, client));
  }
  admitChild(sessionId, cwd, owner) {
    this.db.prepare("UPDATE summarize_workers SET cwd = ?, client = 'claude', owner = ?, state = 'active', last_activity = datetime('now') WHERE session_id = ?").run(cwd, owner, sessionId);
  }
  touch(sessionId) {
    this.db.prepare(`UPDATE summarize_workers SET state = 'active', last_activity = datetime('now')
      WHERE session_id = ? AND state IN ('active', 'abandoned') AND owner IS NOT NULL`).run(sessionId);
  }
  finish(sessionId, state = "finished") {
    this.db.prepare("UPDATE summarize_workers SET state = ?, last_activity = datetime('now') WHERE session_id = ?").run(state, sessionId);
  }
  /** A clear revokes the old owner before replacement enrollment, even if that fails. */
  finishOwner(owner) {
    this.db.prepare("UPDATE summarize_workers SET state = 'finished', last_activity = datetime('now') WHERE owner = ?").run(owner);
  }
  register(input, beforeCommit) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const existing = this.list().find((worker) => worker.session_id === input.sessionId);
      if (existing && (existing.state !== "active" || existing.owner !== input.owner || existing.client !== input.client || existing.cwd !== input.cwd)) {
        throw new Error("Worker enrollment cannot resume, reactivate or change an existing session owner. Start a fresh dedicated session.");
      }
      const history = this.db.prepare(`WITH RECURSIVE sessions(id) AS (
        SELECT ? UNION SELECT session_id FROM conversations JOIN sessions ON parent_session_id = sessions.id
      ) SELECT 1 FROM messages JOIN conversations USING(conversation_id) JOIN sessions ON session_id = sessions.id
        UNION ALL SELECT 1 FROM summaries JOIN conversations USING(conversation_id) JOIN sessions ON session_id = sessions.id
        UNION ALL SELECT 1 FROM promoted JOIN sessions ON session_id = sessions.id LIMIT 1`).get(input.sessionId);
      if (history) throw new Error("Worker enrollment refuses an existing conversation. Start a fresh dedicated session; do not resume, continue or fork.");
      if (input.replaceOwner) this.db.prepare(`UPDATE summarize_workers SET state = 'finished', last_activity = datetime('now')
        WHERE owner = ? AND session_id != ?`).run(input.owner, input.sessionId);
      this.db.prepare(`INSERT INTO summarize_workers(session_id, cwd, client, owner, state)
        VALUES (?, ?, ?, ?, 'active') ON CONFLICT(session_id) DO UPDATE SET
        owner = excluded.owner, state = 'active', last_activity = datetime('now')`).run(input.sessionId, input.cwd, input.client, input.owner);
      const sessions = this.db.prepare(`WITH RECURSIVE descendants(id) AS (
        SELECT ? UNION SELECT session_id FROM conversations JOIN descendants ON parent_session_id = descendants.id
      ) SELECT id FROM descendants`).all(input.sessionId);
      for (const { id } of sessions) {
        this.db.prepare("INSERT OR IGNORE INTO summarize_workers(session_id, cwd, client, state) VALUES (?, ?, ?, 'abandoned')").run(id, input.cwd, input.client);
        this.db.prepare("INSERT OR IGNORE INTO session_ingest_log(session_id) VALUES (?)").run(id);
      }
      beforeCommit?.();
      const { n } = this.db.prepare("SELECT count(*) AS n FROM promoted WHERE session_id IS NULL AND source_summary_id IS NULL").get();
      this.db.exec("COMMIT");
      return { sessions: sessions.map((row) => row.id), unprovenanced: n };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  /**
   * A copied claim is a claim call whose paired result carries a job this daemon issued.
   * `record` keeps this batch's claims for a later result; only the session's own transcript records.
   */
  detectCopiedClaim(sessionId, messages, record = true) {
    const claims = new Set(messages.flatMap((message) => message.workerClaims ?? []));
    if (record) for (const id of claims) {
      this.db.prepare("INSERT OR IGNORE INTO worker_claim_markers(session_id, call_id) VALUES (?, ?)").run(sessionId, id);
    }
    return messages.some((message) => (message.workerPayloads ?? []).some(({ callId, jobId }) => this.issuedJob(jobId) && (claims.has(callId) || Boolean(this.db.prepare("SELECT 1 FROM worker_claim_markers WHERE session_id = ? AND call_id = ?").get(sessionId, callId)))));
  }
  /** Records a job handed to a worker, and forgets jobs older than the retention bound. */
  recordIssuedJob(jobId) {
    this.db.prepare(`DELETE FROM worker_issued_jobs WHERE issued_at < datetime('now', '-${ISSUED_JOB_RETENTION_DAYS} days')`).run();
    this.db.prepare("INSERT OR IGNORE INTO worker_issued_jobs(job_id) VALUES (?)").run(jobId);
  }
  issuedJob(jobId) {
    return Boolean(this.db.prepare("SELECT 1 FROM worker_issued_jobs WHERE job_id = ?").get(jobId));
  }
  /** Caller holds a write transaction; refusal preserves history unless disk discovery permits cleanup. */
  exclude(sessionId, cwd = "", client = "claude", purgeHistory = false, copiedClaim = false) {
    this.db.prepare(`INSERT OR IGNORE INTO summarize_workers(session_id, cwd, client, state)
      VALUES (?, ?, ?, 'abandoned')`).run(sessionId, cwd, client);
    if (purgeHistory || copiedClaim) {
      this.db.prepare("UPDATE summarize_workers SET exclusion_reason = ?, cwd = ? WHERE session_id = ?").run(purgeHistory ? "discovered-descendant" : "copied-claim", cwd, sessionId);
    }
    if (!purgeHistory) {
      this.db.prepare("INSERT OR IGNORE INTO session_ingest_log(session_id) VALUES (?)").run(sessionId);
      return;
    }
    this.db.prepare(`DELETE FROM promoted_fts WHERE rowid IN (SELECT rowid FROM promoted
      WHERE session_id = ? OR source_summary_id IN (SELECT summary_id FROM summaries
        JOIN conversations USING(conversation_id) WHERE session_id = ?))`).run(sessionId, sessionId);
    this.db.prepare(`DELETE FROM promoted WHERE session_id = ? OR source_summary_id IN (
      SELECT summary_id FROM summaries JOIN conversations USING(conversation_id) WHERE session_id = ?)`).run(sessionId, sessionId);
    const conversations = this.db.prepare("SELECT conversation_id FROM conversations WHERE session_id = ?").all(sessionId);
    for (const { conversation_id } of conversations) clearConversationForRebuild(this.db, conversation_id, sessionId);
    this.db.prepare("INSERT OR IGNORE INTO session_ingest_log(session_id) VALUES (?)").run(sessionId);
  }
};

// ../_research/lcm-full-20261021/src/daemon/project-queue.ts
function yieldToEventLoop() {
  return new Promise((resolve) => setImmediate(resolve));
}

// ../_research/lcm-full-20261021/src/store/commit-store.ts
var reference = (row) => ({
  sessionId: row.session_id,
  messageId: row.message_id,
  hash: row.hash,
  subject: row.subject,
  authorAt: row.author_at,
  committedAt: row.committed_at,
  branch: row.branch,
  resolved: row.resolved === 1,
  evidence: row.evidence,
  evidenceValue: row.evidence_value
});
var CANDIDATE_PAGE_SIZE = 256;
var OUTPUT_HASH_PREFILTER = "*[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*";
var CommitStore = class {
  constructor(db) {
    this.db = db;
  }
  db;
  isCurrentDeclaration(candidate) {
    return this.db.prepare(`SELECT 1 FROM session_web_urls u JOIN conversations c USING(session_id)
      JOIN messages m USING(conversation_id)
      WHERE u.session_id = ? AND u.url = ? AND m.message_id = ? AND c.is_timeline = 0
        AND NOT EXISTS (SELECT 1 FROM message_parts p WHERE p.message_id = m.message_id AND p.part_type = 'compaction')`).get(candidate.session_id, candidate.url, candidate.message_id) !== void 0;
  }
  async *declarationPages() {
    let sessionId = "", url = "";
    const page = this.db.prepare(`SELECT u.session_id, u.url, m.message_id, m.conversation_id
      FROM session_web_urls u JOIN messages m ON m.message_id = (
        SELECT first.message_id FROM messages first JOIN conversations c USING(conversation_id)
        WHERE c.session_id = u.session_id AND c.is_timeline = 0
          AND NOT EXISTS (SELECT 1 FROM message_parts p WHERE p.message_id = first.message_id AND p.part_type = 'compaction')
        ORDER BY first.message_id LIMIT 1
      )
      WHERE (u.session_id, u.url) > (?, ?) ORDER BY u.session_id, u.url LIMIT ${CANDIDATE_PAGE_SIZE}`);
    for (; ; ) {
      const rows = page.all(sessionId, url);
      if (rows.length) yield rows;
      await yieldToEventLoop();
      if (rows.length < CANDIDATE_PAGE_SIZE) return;
      ({ session_id: sessionId, url } = rows.at(-1));
    }
  }
  isCurrentCandidate(candidate) {
    const row = this.db.prepare(`SELECT m.role, m.content,
      (SELECT group_concat(p.tool_output, char(10)) FROM message_parts p WHERE p.message_id = m.message_id
        AND p.part_type = 'tool' AND p.session_id = c.session_id AND p.tool_output IS NOT NULL) tool_output
      FROM messages m JOIN conversations c USING(conversation_id)
      WHERE m.message_id = ? AND m.conversation_id = ? AND c.session_id = ? AND c.is_timeline = 0
        AND NOT EXISTS (SELECT 1 FROM message_parts p WHERE p.message_id = m.message_id AND p.part_type = 'compaction')`).get(candidate.message_id, candidate.conversation_id, candidate.session_id);
    return row !== void 0 && row.role === candidate.role && row.content === candidate.content && row.tool_output === candidate.tool_output;
  }
  async *candidatePages() {
    let id = 0;
    const page = this.db.prepare(`SELECT m.message_id, m.conversation_id, c.session_id, m.role, m.content,
      (SELECT group_concat(p.tool_output, char(10)) FROM message_parts p WHERE p.message_id = m.message_id
        AND p.part_type = 'tool' AND p.session_id = c.session_id AND p.tool_output IS NOT NULL) tool_output
      FROM messages m JOIN conversations c USING(conversation_id)
      WHERE m.message_id > ? AND c.is_timeline = 0
        AND NOT EXISTS (SELECT 1 FROM message_parts p WHERE p.message_id = m.message_id AND p.part_type = 'compaction')
        AND ((m.role = 'tool' AND (m.content LIKE '%[%]%' OR m.content LIKE '%commit %' OR lower(m.content) GLOB '${OUTPUT_HASH_PREFILTER}'))
          OR EXISTS (SELECT 1 FROM message_parts p WHERE p.message_id = m.message_id AND p.part_type = 'tool' AND p.session_id = c.session_id
            AND (p.tool_output LIKE '%[%]%' OR p.tool_output LIKE '%commit %' OR lower(p.tool_output) GLOB '${OUTPUT_HASH_PREFILTER}')))
      ORDER BY m.message_id LIMIT ${CANDIDATE_PAGE_SIZE}`);
    for (; ; ) {
      const rows = page.all(id);
      if (rows.length) yield rows;
      await yieldToEventLoop();
      if (rows.length < CANDIDATE_PAGE_SIZE) return;
      id = rows.at(-1).message_id;
    }
  }
  async *referencePages() {
    let id = 0;
    for (; ; ) {
      const rows = this.db.prepare(`SELECT rowid reference_id, * FROM session_commits WHERE rowid > ?
        ORDER BY rowid LIMIT ${CANDIDATE_PAGE_SIZE}`).all(id);
      if (rows.length) yield rows.map(reference);
      await yieldToEventLoop();
      if (rows.length < CANDIDATE_PAGE_SIZE) return;
      id = rows.at(-1).reference_id;
    }
  }
  markUnresolved(ref) {
    this.db.prepare(`UPDATE session_commits SET resolved = 0
      WHERE message_id = ? AND evidence = ? AND evidence_value = ? AND hash = ?`).run(ref.messageId, ref.evidence, ref.evidenceValue, ref.hash);
    if (ref.evidence !== "commit-output") return null;
    const changed = this.db.prepare(`UPDATE messages SET event_at = NULL, event_time_source = NULL
      WHERE message_id = ? AND event_time_source = 'commit' AND NOT EXISTS (
        SELECT 1 FROM session_commits WHERE message_id = messages.message_id AND evidence = 'commit-output'
          AND resolved = 1 AND julianday(committed_at) = julianday(messages.event_at)
      ) RETURNING conversation_id`).get(ref.messageId);
    return changed?.conversation_id ?? null;
  }
  find(key) {
    const trailer = key.evidence === "session-trailer";
    const row = this.db.prepare(`SELECT * FROM session_commits WHERE ${trailer ? "session_id" : "message_id"} = ? AND evidence = ?
      ${trailer ? "" : "AND evidence_value = ?"} ${key.hash ? "AND hash = ?" : ""} LIMIT 1`).get(
      trailer ? key.sessionId : key.messageId,
      key.evidence,
      ...trailer ? [] : [key.evidenceValue],
      ...key.hash ? [key.hash] : []
    );
    return row ? reference(row) : null;
  }
  record(ref) {
    const prior = ref.evidence === "session-trailer" ? this.find(ref) : null;
    this.db.prepare(`INSERT INTO session_commits(session_id, message_id, hash, subject, author_at, committed_at, branch, resolved, evidence, evidence_value)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(message_id, evidence, evidence_value, hash)
      DO UPDATE SET resolved = excluded.resolved, committed_at = excluded.committed_at`).run(
      ref.sessionId,
      prior?.messageId ?? ref.messageId,
      ref.hash,
      ref.subject,
      ref.authorAt,
      ref.committedAt,
      ref.branch,
      Number(ref.resolved),
      ref.evidence,
      prior?.evidenceValue ?? ref.evidenceValue
    );
  }
  anchor(messageId, ref) {
    const date = ref?.evidence === "commit-output" && ref.resolved && this.find(ref)?.resolved ? ref.committedAt : null;
    return Number(this.db.prepare(`UPDATE messages SET event_at = ?, event_time_source = ?
      WHERE message_id = ? AND (event_time_source = 'commit' OR event_at IS NULL)
        AND (event_at IS NOT ? OR event_time_source IS NOT ?)`).run(date, date ? "commit" : null, messageId, date, date ? "commit" : null).changes);
  }
  needsEvidenceRepair() {
    this.db.exec("CREATE TABLE IF NOT EXISTS commit_evidence_backfill (id INTEGER PRIMARY KEY CHECK(id = 1))");
    return !this.db.prepare("SELECT 1 FROM commit_evidence_backfill WHERE id = 1").get();
  }
  repairLegacyEvidence() {
    this.db.prepare(`UPDATE messages SET event_at = NULL, event_time_source = NULL
      WHERE event_time_source = 'commit' AND message_id IN (SELECT message_id FROM session_commits)
        AND ((SELECT COUNT(DISTINCT hash) FROM session_commits WHERE message_id = messages.message_id
          AND evidence = 'commit-output') != 1 OR NOT EXISTS (
          SELECT 1 FROM session_commits WHERE message_id = messages.message_id AND evidence = 'commit-output'
            AND resolved = 1 AND (committed_at IS NULL OR julianday(committed_at) = julianday(messages.event_at))
        ))`).run();
    this.db.exec(`DELETE FROM session_commits WHERE evidence = 'session-trailer' AND rowid NOT IN (
      SELECT MIN(rowid) FROM session_commits WHERE evidence = 'session-trailer' GROUP BY session_id, hash
    );
    CREATE UNIQUE INDEX IF NOT EXISTS session_commits_trailer_idx ON session_commits(session_id, hash)
      WHERE evidence = 'session-trailer';`);
  }
  /** Every conversation of a session with commit evidence: the same set on any rerun. */
  conversationsWithCommits() {
    return this.db.prepare(`SELECT conversation_id FROM conversations
      WHERE session_id IN (SELECT DISTINCT session_id FROM session_commits) ORDER BY conversation_id`).all().map((row) => row.conversation_id);
  }
  finishEvidenceRepair() {
    this.db.prepare("INSERT INTO commit_evidence_backfill (id) VALUES (1)").run();
  }
  repairTrailerIdentityOnce() {
    this.db.exec("CREATE TABLE IF NOT EXISTS session_trailer_identity_backfill (id INTEGER PRIMARY KEY CHECK(id = 1))");
    if (this.db.prepare("SELECT 1 FROM session_trailer_identity_backfill WHERE id = 1").get()) return;
    this.db.prepare("DELETE FROM session_commits WHERE evidence = 'session-trailer'").run();
    this.db.prepare("INSERT INTO session_trailer_identity_backfill (id) VALUES (1)").run();
  }
  forSession(sessionId) {
    if (!this.db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'session_commits'").get()) return [];
    return this.db.prepare("SELECT * FROM session_commits WHERE session_id = ? ORDER BY committed_at, hash, message_id, evidence").all(sessionId).map(reference);
  }
  forSummary(summaryId) {
    if (!this.db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'session_commits'").get()) return [];
    return this.db.prepare(`SELECT * FROM session_commits WHERE session_id IN (
      SELECT c.session_id FROM summaries s JOIN conversations c USING(conversation_id)
        WHERE s.summary_id IN (${SUMMARY_SOURCE_IDS_SQL}) AND c.is_timeline = 0
      UNION SELECT session_id FROM timeline_sources WHERE summary_id = ?
    ) ORDER BY committed_at, hash, message_id, evidence`).all(summaryId, summaryId).map(reference);
  }
};

// ../_research/lcm-full-20261021/src/promotion/tool-lessons.ts
import { basename } from "node:path";

// ../_research/lcm-full-20261021/src/promotion/tool-lesson-projection.ts
var BATCH_SIZE = 128;
var ENVIRONMENT_SESSION_THRESHOLD = 3;
var REFRESH_TIME_BUDGET_MS = 10;
var LessonRefreshBudget = class {
  started = performance.now();
  exhausted() {
    return performance.now() - this.started >= REFRESH_TIME_BUDGET_MS;
  }
  async yield() {
    await yieldToEventLoop();
    this.started = performance.now();
  }
};
function callOrder(call) {
  return call.seen + String(call.message_id).padStart(16, "0") + String(call.row_id).padStart(16, "0");
}
function lessonKey(lesson) {
  return JSON.stringify(lesson.kind === "error-fix" ? [lesson.kind, lesson.shape, lesson.failedCommand, lesson.succeededCommand] : [lesson.kind, lesson.shape ?? lesson.reason]);
}
function withLessonTransaction(db, work) {
  db.exec("SAVEPOINT tool_lesson_update");
  try {
    work();
    db.exec("RELEASE tool_lesson_update");
  } catch (error) {
    db.exec("ROLLBACK TO tool_lesson_update; RELEASE tool_lesson_update");
    throw error;
  }
}
var ToolLessonProjection = class {
  constructor(db) {
    this.db = db;
  }
  db;
  replaceContribution(row, kind, evidence) {
    const call = evidence?.call, lesson = evidence?.lesson;
    const old = this.db.prepare("SELECT * FROM tool_lesson_contributions WHERE call_row = ? AND kind = ?").get(row, kind);
    const data = lesson && JSON.stringify(lesson);
    if (old?.data === data) return;
    if (old) {
      this.db.prepare("DELETE FROM tool_lesson_contributions WHERE call_row = ? AND kind = ?").run(row, kind);
      this.adjustTotal(old.lesson_key, { lesson: JSON.parse(old.data), session: old.session_id }, -1);
    }
    if (lesson && call) {
      const key = lessonKey(lesson);
      this.db.prepare("INSERT INTO tool_lesson_contributions VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(row, kind, key, call.session_id, lesson.firstSeen, lesson.lastSeen, callOrder(call), data);
      this.adjustTotal(key, { lesson, session: call.session_id }, 1);
    }
  }
  adjustTotal(key, evidence, delta) {
    const { lesson, session } = evidence;
    const row = this.db.prepare("SELECT data FROM tool_lesson_totals WHERE lesson_key = ?").get(key);
    const total = row ? JSON.parse(row.data) : { ...lesson, count: 0, sessionCounts: /* @__PURE__ */ Object.create(null) };
    total.count += delta;
    const count = (Object.hasOwn(total.sessionCounts, session) ? total.sessionCounts[session] : 0) + delta;
    if (count) Object.defineProperty(total.sessionCounts, session, { value: count, enumerable: true, writable: true, configurable: true });
    else delete total.sessionCounts[session];
    this.db.prepare(`INSERT INTO tool_lesson_totals (lesson_key, data) VALUES (?, ?)
      ON CONFLICT(lesson_key) DO UPDATE SET data = excluded.data, dirty = 1`).run(key, JSON.stringify(total));
    if (lesson.kind === "error-fix") this.db.prepare("UPDATE tool_lesson_progress SET pair_count = pair_count + ? WHERE singleton = 1").run(delta);
  }
  dirtyEnvironment(shape) {
    this.db.prepare("UPDATE tool_lesson_totals SET dirty = 1 WHERE lesson_key = ?").run(JSON.stringify(["environment-rule", shape]));
  }
  removeSuccess(row) {
    const old = this.db.prepare("SELECT shape FROM tool_lesson_successes WHERE call_row = ?").get(row);
    if (!old) return;
    this.db.prepare("DELETE FROM tool_lesson_successes WHERE call_row = ?").run(row);
    this.dirtyEnvironment(old.shape);
  }
  recordSuccess(call, shape) {
    this.db.prepare("INSERT INTO tool_lesson_successes VALUES (?, ?, ?, ?, ?)").run(call.row_id, call.session_id, shape, callOrder(call), call.seen);
    this.dirtyEnvironment(shape);
  }
  aggregate(key, data) {
    const lesson = JSON.parse(data);
    if (!lesson.count || lesson.kind === "environment-rule" && Object.keys(lesson.sessionCounts).length < ENVIRONMENT_SESSION_THRESHOLD) return null;
    lesson.firstSeen = String(this.db.prepare("SELECT first_seen FROM tool_lesson_contributions WHERE lesson_key = ? ORDER BY first_seen LIMIT 1").get(key).first_seen);
    lesson.lastSeen = String(this.db.prepare("SELECT last_seen FROM tool_lesson_contributions WHERE lesson_key = ? ORDER BY last_seen DESC LIMIT 1").get(key).last_seen);
    lesson.retired = false;
    if (lesson.kind === "environment-rule") this.retireEnvironment(key, lesson);
    return lesson;
  }
  retireEnvironment(key, lesson) {
    const first = this.db.prepare("SELECT call_order FROM tool_lesson_contributions WHERE lesson_key = ? ORDER BY call_order LIMIT 1").get(key);
    const success = this.db.prepare("SELECT call_order, seen FROM tool_lesson_successes WHERE shape = ? ORDER BY call_order DESC LIMIT 1").get(lesson.shape);
    if (!success || success.call_order <= String(first.call_order)) return;
    lesson.retired = true;
    lesson.lastSeen = lesson.lastSeen > success.seen ? lesson.lastSeen : success.seen;
  }
  async publish(generation, budget = new LessonRefreshBudget()) {
    const page = this.db.prepare("SELECT lesson_key, data FROM tool_lesson_totals WHERE dirty = 1 AND lesson_key > ? ORDER BY lesson_key LIMIT ?");
    const insert = this.db.prepare("INSERT OR REPLACE INTO tool_lessons (generation, lesson_key, kind, retired, last_seen, data) VALUES (?, ?, ?, ?, ?, ?)");
    let cursor = "";
    while (true) {
      const rows = page.all(cursor, BATCH_SIZE);
      if (!rows.length) break;
      for (const row of rows) {
        withLessonTransaction(this.db, () => {
          const lesson = this.aggregate(row.lesson_key, row.data);
          insert.run(generation, row.lesson_key, lesson?.kind ?? "deleted", Number(lesson?.retired ?? true), lesson?.lastSeen ?? "", JSON.stringify(lesson));
        });
        if (budget.exhausted()) await budget.yield();
      }
      cursor = rows[rows.length - 1].lesson_key;
      await budget.yield();
    }
    withLessonTransaction(this.db, () => {
      this.db.prepare(`INSERT INTO tool_lesson_state (singleton, generation) VALUES (1, ?)
        ON CONFLICT(singleton) DO UPDATE SET generation = excluded.generation`).run(generation);
      this.db.prepare("UPDATE tool_lesson_progress SET pending = 0 WHERE singleton = 1").run();
    });
    cursor = "";
    while (true) {
      const rows = page.all(cursor, BATCH_SIZE);
      if (!rows.length) break;
      for (const row of rows) {
        withLessonTransaction(this.db, () => {
          this.db.prepare("DELETE FROM tool_lessons WHERE lesson_key = ? AND generation < ?").run(row.lesson_key, generation);
          this.db.prepare("DELETE FROM tool_lessons WHERE lesson_key = ? AND generation = ? AND kind = 'deleted'").run(row.lesson_key, generation);
          this.db.prepare("UPDATE tool_lesson_totals SET dirty = 0 WHERE lesson_key = ?").run(row.lesson_key);
          this.db.prepare("DELETE FROM tool_lesson_totals WHERE lesson_key = ? AND json_extract(data, '$.count') = 0").run(row.lesson_key);
        });
        if (budget.exhausted()) await budget.yield();
      }
      cursor = rows[rows.length - 1].lesson_key;
      await budget.yield();
    }
  }
};

// ../_research/lcm-full-20261021/src/promotion/tool-lessons.ts
var SUBCOMMAND_TOOLS = /* @__PURE__ */ new Set(["git", "npm", "pnpm", "yarn", "pip", "pip3", "brew", "cargo", "docker", "kubectl", "gh", "lcm"]);
var SHELL_WRAPPERS = /* @__PURE__ */ new Set(["sh", "bash", "zsh"]);
var ASSIGNMENT = /^[a-zA-Z_][\w]*=/;
var MAX_WRAPPER_DEPTH = 8;
function commandWords(command) {
  if (command.startsWith("[")) {
    try {
      const words2 = JSON.parse(command);
      return Array.isArray(words2) && words2.every((word2) => typeof word2 === "string") ? words2 : null;
    } catch {
      return null;
    }
  }
  const words = [];
  const quotedAt = [];
  let word = "", quote2 = "", started = false, firstQuote = -1;
  const finishWord = () => {
    if (started) {
      words.push(word);
      quotedAt.push(firstQuote);
    }
    word = "";
    started = false;
    firstQuote = -1;
  };
  for (let index = 0; index < command.length; index++) {
    const char = command[index];
    if (char === "\\" && quote2 !== "'") {
      if (firstQuote < 0) firstQuote = word.length;
      if (++index === command.length) return null;
      word += command[index];
      started = true;
      continue;
    }
    if (quote2) {
      if (char === quote2) quote2 = "";
      else {
        if (quote2 === '"' && /[$`]/.test(char)) return null;
        word += char;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      if (firstQuote < 0) firstQuote = word.length;
      quote2 = char;
      started = true;
      continue;
    }
    if (/[;&|<>$`\n\r()]/.test(char)) return null;
    if (/\s/.test(char)) {
      finishWord();
      continue;
    }
    word += char;
    started = true;
  }
  if (quote2) return null;
  finishWord();
  if (!words.length) return null;
  const executableIndex = words.findIndex((value, index) => !ASSIGNMENT.test(value) || quotedAt[index] >= 0 && quotedAt[index] <= value.indexOf("="));
  if (executableIndex >= 0 && ASSIGNMENT.test(words[executableIndex])) return null;
  const wrapper = executableIndex >= 0 && SHELL_WRAPPERS.has(basename(words[executableIndex]));
  return words.map((value, index) => {
    if (index <= executableIndex) return value;
    if (wrapper || quotedAt[index] < 0) return value;
    if (/^-[a-zA-Z]/.test(value) && quotedAt[index] >= 2) return value;
    if (/^--[a-zA-Z][\w-]*=/.test(value) && quotedAt[index] > value.indexOf("=")) return value;
    return "<args>";
  });
}
function commandSegments(command) {
  if (command.startsWith("[")) return [{ command, operator: "" }];
  const segments = [];
  let quote2 = "", start = 0;
  for (let index = 0; index < command.length; index++) {
    const char = command[index];
    if (char === "\\" && quote2 !== "'") {
      if (++index === command.length) return null;
      continue;
    }
    if (quote2) {
      if (char === quote2) quote2 = "";
      else if (quote2 === '"' && /[$`]/.test(char)) return null;
      continue;
    }
    if (char === "'" || char === '"') {
      quote2 = char;
      continue;
    }
    if (char === "#" && (index === start || /\s/.test(command[index - 1]))) return null;
    if (/[<>$`\n\r()]/.test(char)) return null;
    if (/[;&|]/.test(char)) {
      let operator = char;
      if ((char === "&" || char === "|") && command[index + 1] === char) operator += char;
      else if (char === "&") return null;
      const segment = command.slice(start, index).trim();
      if (!segment) return null;
      segments.push({ command: segment, operator });
      index += operator.length - 1;
      start = index + 1;
    }
  }
  if (quote2) return null;
  const last = command.slice(start).trim();
  if (!last) return null;
  segments.push({ command: last, operator: "" });
  return segments;
}
var GLOBAL_VALUE_FLAGS = /* @__PURE__ */ new Set(["-C", "-c", "--prefix", "--cwd", "--directory", "--git-dir", "--work-tree", "--config"]);
function subcommandIndex(words, executable) {
  if (!SUBCOMMAND_TOOLS.has(executable)) return -1;
  for (let index = 1; index < words.length; index++) {
    const word = words[index];
    if (word === "--") return -1;
    if (GLOBAL_VALUE_FLAGS.has(word)) {
      index++;
      continue;
    }
    if (word.startsWith("-")) continue;
    return /^[a-z][\w-]*$/.test(word) ? index : -1;
  }
  return -1;
}
function shapeFlag(word, executable) {
  if (/^-[a-zA-Z].+/.test(word)) {
    if (executable === "rm" && /^-[dfiPRrvW]+$/.test(word)) return { name: word, hasValue: false };
    return { name: word.slice(0, 2), hasValue: true };
  }
  const equals = word.indexOf("=");
  if (equals >= 0) return { name: word.slice(0, equals), hasValue: true };
  return { name: word, hasValue: false };
}
function simpleCommandShape(words) {
  const executable = basename(words[0]);
  if (!/^[a-zA-Z][\w.-]*$/.test(executable)) return null;
  if (["sh", "bash", "zsh", "env", "sudo", "xargs"].includes(executable)) return null;
  const parts = [executable];
  const subcommand = subcommandIndex(words, executable);
  if (subcommand > 0) parts.push(words[subcommand]);
  const flags = /* @__PURE__ */ new Set();
  let hasValues = false, positional = false;
  for (let index = 1; index < words.length; index++) {
    if (index === subcommand) continue;
    const word = words[index];
    if (word === "--") {
      positional = true;
      continue;
    }
    if (!positional && (/^-[a-zA-Z]/.test(word) || /^--[a-zA-Z][\w-]*(?:=.*)?$/.test(word))) {
      const flag = shapeFlag(word, executable);
      flags.add(flag.name);
      hasValues ||= flag.hasValue;
    } else hasValues = true;
  }
  return [...parts, ...[...flags].sort(), ...hasValues ? ["<args>"] : []].join(" ");
}
function shellCommandShape(command, depth) {
  if (depth > MAX_WRAPPER_DEPTH) return null;
  const segments = commandSegments(command.trim());
  if (!segments) return null;
  const parts = [];
  for (const segment of segments) {
    const parsed = commandWords(segment.command);
    if (!parsed) return null;
    let start = 0;
    while (start < parsed.length && ASSIGNMENT.test(parsed[start])) start++;
    const words = parsed.slice(start);
    if (!words.length) return null;
    const executable = basename(words[0]);
    if (!parts.length && executable === "cd" && words.length === 2 && (segment.operator === "&&" || segment.operator === ";")) continue;
    let shape;
    if (SHELL_WRAPPERS.has(executable)) {
      if (words.length !== 3 || !["-c", "-lc", "-cl"].includes(words[1])) return null;
      shape = shellCommandShape(words[2], depth + 1);
      if (shape && (parts.length > 0 || segment.operator) && / [;&|]+ /.test(shape)) shape = `(${shape})`;
    } else shape = simpleCommandShape(words);
    if (!shape) return null;
    parts.push(shape);
    if (segment.operator) parts.push(segment.operator);
  }
  return parts.length ? parts.join(" ") : null;
}
function commandShape(command) {
  return shellCommandShape(command, 0);
}
var CALL_WINDOW = 20;
function observe(lesson, call) {
  lesson.count++;
  lesson.sessionCounts[call.session_id] = (lesson.sessionCounts[call.session_id] ?? 0) + 1;
  lesson.firstSeen = lesson.firstSeen < call.seen ? lesson.firstSeen : call.seen;
  lesson.lastSeen = lesson.lastSeen > call.seen ? lesson.lastSeen : call.seen;
}
function newLesson(kind, call, project) {
  const type2 = kind === "error-fix" ? "solution" : kind === "block-reason" ? "gotcha" : "environment";
  return {
    kind,
    count: 0,
    sessionCounts: /* @__PURE__ */ Object.create(null),
    firstSeen: call.seen,
    lastSeen: call.seen,
    retired: false,
    tags: [`type:${type2}`, "source:tool-calls", `project:${project}`]
  };
}
function maskBlockReason(reason) {
  return reason.split(/\r?\n/, 1)[0].replace(/(?:[A-Za-z]:[\\/]|(?:~|\.\.?)?\/)[^\s"'<>]+|\b[\w.-]+\/[^\s"'<>]+/g, "<path>").replace(/\b[\w-]+\.[\w.-]+\b/g, "<path>").replace(/\b(?:session|call|request)[_-][\w-]+\b/gi, "<id>").replace(/\b(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{8,})\b/gi, "<id>").replace(/(\b(?:[\w-]*id|pid|session|call|request)[=:]\s*)[^\s,;]+/gi, "$1<id>").replace(/\b\d+\b/g, "<id>");
}
function callShape(call) {
  if (!SHELL_TOOLS.includes(call.name.replace(/^functions\./, "").toLowerCase()) || call.input === null || call.truncated) return null;
  return commandShape(call.input);
}
function blockLesson(call, project) {
  if (!SHELL_TOOLS.includes(call.name.replace(/^functions\./, "").toLowerCase())) return;
  if (call.outcome !== "blocked" || !call.block_reason) return;
  const lesson = { ...newLesson("block-reason", call, project), reason: maskBlockReason(call.block_reason) };
  observe(lesson, call);
  return lesson;
}
function environmentLesson(call, project, shape = callShape(call)) {
  if (!shape || call.outcome !== "failed" && call.outcome !== "blocked") return;
  const lesson = { ...newLesson("environment-rule", call, project), shape };
  observe(lesson, call);
  return lesson;
}
var CALL_SELECT = `SELECT t.rowid AS row_id, t.*,
  COALESCE(strftime('%Y-%m-%dT%H:%M:%fZ', m.event_at), strftime('%Y-%m-%dT%H:%M:%fZ', m.created_at)) AS seen
  FROM transcript_tool_calls t JOIN messages m ON m.message_id = t.message_id`;
var ToolLessonStore = class {
  constructor(db) {
    this.db = db;
    this.projection = new ToolLessonProjection(db);
  }
  db;
  projection;
  /** Pairs and block reasons from the selected messages' calls alone; the window is that set, never the project snapshot. */
  async forMessages(messageIds) {
    const ids = [...new Set(messageIds)].sort((a, b) => a - b);
    const calls = [];
    for (let offset = 0; offset < ids.length; offset += BATCH_SIZE) {
      const page = ids.slice(offset, offset + BATCH_SIZE);
      calls.push(...this.db.prepare(CALL_SELECT + ` WHERE t.message_id IN (${page.map(() => "?").join(",")})`).all(...page));
      await yieldToEventLoop();
    }
    calls.sort((a, b) => (a.session_id < b.session_id ? -1 : a.session_id > b.session_id ? 1 : 0) || a.message_id - b.message_id || a.row_id - b.row_id);
    const lessons = /* @__PURE__ */ new Map();
    const merge2 = (lesson, call) => {
      const key = lesson.kind === "block-reason" ? JSON.stringify([lesson.command, lesson.reason]) : lessonKey(lesson);
      const existing = lessons.get(key);
      if (!existing) return lessons.set(key, lesson);
      observe(existing, call);
      existing.lastSeen = existing.lastSeen > lesson.lastSeen ? existing.lastSeen : lesson.lastSeen;
    };
    calls.forEach((call, index) => {
      const block = blockLesson(call, "");
      if (block && call.input !== null) merge2({ ...block, kind: "block-reason", command: call.input, reason: block.reason }, call);
      const shape = callShape(call);
      if (!shape || call.outcome !== "failed" && call.outcome !== "blocked") return;
      const window = calls.slice(index + 1, index + 1 + CALL_WINDOW).filter((next) => next.session_id === call.session_id);
      const success = window.find((next) => next.outcome === "succeeded" && callShape(next) === shape);
      if (!success) return;
      const pair = { ...newLesson("error-fix", call, ""), kind: "error-fix", shape, failedCommand: call.input, succeededCommand: success.input };
      observe(pair, call);
      pair.lastSeen = pair.lastSeen > success.seen ? pair.lastSeen : success.seen;
      merge2(pair, call);
    });
    return [...lessons.values()];
  }
  async refresh(project) {
    const budget = new LessonRefreshBudget();
    const state = this.db.prepare("SELECT generation FROM tool_lesson_state WHERE singleton = 1").get();
    const invalid = this.db.prepare("SELECT session_id FROM tool_lesson_invalid_sessions ORDER BY session_id LIMIT 1");
    while (true) {
      const session = invalid.get();
      if (!session) break;
      await this.invalidateSession(session.session_id, budget);
    }
    await this.refreshChanges(project, budget);
    const pending = this.db.prepare("SELECT pending FROM tool_lesson_progress WHERE singleton = 1").get().pending;
    if (state && !pending && !this.db.prepare("SELECT 1 FROM tool_lesson_totals WHERE dirty = 1 LIMIT 1").get()) return 0;
    await this.projection.publish((state?.generation ?? 0) + 1, budget);
    return Number(this.db.prepare("SELECT pair_count FROM tool_lesson_progress WHERE singleton = 1").get().pair_count);
  }
  async refreshChanges(project, budget) {
    const changes = this.db.prepare(`SELECT c.session_id, c.call_id FROM tool_lesson_changes c
      LEFT JOIN transcript_tool_calls t ON t.session_id = c.session_id AND t.call_id = c.call_id
      ORDER BY c.session_id, t.message_id, t.rowid LIMIT ?`);
    const callById = this.db.prepare(CALL_SELECT + `
      WHERE t.session_id = ? AND t.call_id = ?
      AND NOT EXISTS (SELECT 1 FROM summarize_workers w WHERE w.session_id = t.session_id)`);
    const predecessors = this.db.prepare(CALL_SELECT + `
      WHERE t.session_id = ? AND (t.message_id, t.rowid) < (?, ?)
      ORDER BY t.message_id DESC, t.rowid DESC LIMIT ?`);
    let frontier;
    while (true) {
      const page = changes.all(BATCH_SIZE);
      if (!page.length) break;
      if (budget.exhausted()) await budget.yield();
      const affected = /* @__PURE__ */ new Map();
      const shapes = /* @__PURE__ */ new Map();
      const shapeOf = (call) => {
        if (!shapes.has(call.row_id)) shapes.set(call.row_id, callShape(call));
        return shapes.get(call.row_id);
      };
      let last = frontier;
      for (const change of page) {
        const call = callById.get(change.session_id, change.call_id);
        if (!call) continue;
        withLessonTransaction(this.db, () => this.updateCall(call, project, shapeOf(call)));
        if (budget.exhausted()) await budget.yield();
        affected.set(call.row_id, call);
        const previous = predecessors.all(call.session_id, call.message_id, call.row_id, CALL_WINDOW);
        for (const prior of previous) {
          if (frontier?.session_id === prior.session_id && (prior.message_id < frontier.message_id || prior.message_id === frontier.message_id && prior.row_id <= frontier.row_id)) continue;
          affected.set(prior.row_id, prior);
        }
        last = call;
        if (budget.exhausted()) await budget.yield();
      }
      for (const call of affected.values()) {
        withLessonTransaction(this.db, () => this.updatePair(call, project, shapeOf));
        if (budget.exhausted()) await budget.yield();
      }
      withLessonTransaction(this.db, () => {
        for (const change of page) {
          this.db.prepare("DELETE FROM tool_lesson_changes WHERE session_id = ? AND call_id = ?").run(change.session_id, change.call_id);
        }
        this.db.prepare("UPDATE tool_lesson_progress SET pending = 1 WHERE singleton = 1").run();
      });
      frontier = last;
      await budget.yield();
    }
  }
  updateCall(call, project, shape) {
    this.projection.replaceContribution(call.row_id, "block-reason", { call, lesson: blockLesson(call, project) });
    this.projection.replaceContribution(call.row_id, "environment-rule", { call, lesson: environmentLesson(call, project, shape) });
    this.projection.removeSuccess(call.row_id);
    if (shape && call.outcome === "succeeded") {
      this.projection.recordSuccess(call, shape);
    }
  }
  updatePair(call, project, shapeOf) {
    let pair;
    const shape = shapeOf(call);
    if (shape && (call.outcome === "failed" || call.outcome === "blocked")) {
      const window = this.db.prepare(CALL_SELECT + `
        WHERE t.session_id = ? AND (t.message_id, t.rowid) > (?, ?)
        ORDER BY t.message_id, t.rowid LIMIT ?`).all(call.session_id, call.message_id, call.row_id, CALL_WINDOW);
      const success = window.find((next) => next.outcome === "succeeded" && shapeOf(next) === shape);
      if (success) {
        pair = {
          ...newLesson("error-fix", call, project),
          shape,
          failedCommand: call.input,
          succeededCommand: success.input
        };
        observe(pair, call);
        pair.lastSeen = pair.lastSeen > success.seen ? pair.lastSeen : success.seen;
      }
    }
    this.projection.replaceContribution(call.row_id, "error-fix", { call, lesson: pair });
  }
  /** Only deletion/movement/exclusion replays a session, including pairs whose window shrank. */
  async invalidateSession(session, budget) {
    const evidence = this.db.prepare("SELECT call_row, kind FROM tool_lesson_contributions WHERE session_id = ? ORDER BY call_row, kind LIMIT ?");
    while (true) {
      const page = evidence.all(session, BATCH_SIZE);
      if (!page.length) break;
      for (const row of page) {
        withLessonTransaction(this.db, () => this.projection.replaceContribution(row.call_row, row.kind));
        if (budget.exhausted()) await budget.yield();
      }
      await budget.yield();
    }
    const successes = this.db.prepare("SELECT call_row FROM tool_lesson_successes WHERE session_id = ? ORDER BY call_row LIMIT ?");
    while (true) {
      const page = successes.all(session, BATCH_SIZE);
      if (!page.length) break;
      for (const row of page) {
        withLessonTransaction(this.db, () => this.projection.removeSuccess(row.call_row));
        if (budget.exhausted()) await budget.yield();
      }
      await budget.yield();
    }
    withLessonTransaction(this.db, () => {
      this.db.prepare("DELETE FROM tool_lesson_changes WHERE session_id = ?").run(session);
      this.db.prepare(`INSERT OR IGNORE INTO tool_lesson_changes
        SELECT session_id, call_id FROM transcript_tool_calls WHERE session_id = ?
          AND NOT EXISTS (SELECT 1 FROM summarize_workers WHERE session_id = ?)`).run(session, session);
      this.db.prepare("DELETE FROM tool_lesson_invalid_sessions WHERE session_id = ?").run(session);
      this.db.prepare("UPDATE tool_lesson_progress SET pending = 1 WHERE singleton = 1").run();
    });
    if (budget.exhausted()) await budget.yield();
  }
  list(options = {}) {
    return this.db.prepare(`SELECT t.data FROM tool_lessons t
      WHERE t.generation <= (SELECT generation FROM tool_lesson_state WHERE singleton = 1)
        AND t.generation = (SELECT MAX(v.generation) FROM tool_lessons v WHERE v.lesson_key = t.lesson_key
          AND v.generation <= (SELECT generation FROM tool_lesson_state WHERE singleton = 1))
        AND t.kind <> 'deleted' ${options.includeRetired ? "" : "AND t.retired = 0"}
        AND (? IS NULL OR t.kind = ?) ORDER BY t.last_seen DESC, t.lesson_key LIMIT ?`).all(options.kind ?? null, options.kind ?? null, options.limit ?? -1).map((row) => JSON.parse(row.data));
  }
};

// ../_research/lcm-full-20261021/src/db/sqlite-date.ts
function parseSqliteDate(value) {
  return new Date(hasTimezoneMarker(value) ? value : `${value.replace(" ", "T")}Z`);
}
function hasTimezoneMarker(value) {
  return /(?:Z|[+-]\d{2}:?\d{2})$/.test(value.trim());
}

// ../_research/lcm-full-20261021/src/store/conversation-store.ts
import { createHash, randomUUID } from "node:crypto";
import { statSync as statSync2 } from "node:fs";

// ../_research/lcm-full-20261021/src/store/full-text-fallback.ts
var RAW_TERM_RE = /"([^"]+)"|(\S+)/g;
var EDGE_PUNCTUATION_RE = /^[`'"()[\]{}<>.,:;!?*_+=|\\/-]+|[`'"()[\]{}<>.,:;!?*_+=|\\/-]+$/g;
function normalizeFallbackTerm(raw) {
  return raw.trim().replace(EDGE_PUNCTUATION_RE, "").toLowerCase();
}
function escapeLike(term) {
  return term.replace(/([\\%_])/g, "\\$1");
}
function buildLikeSearchPlan(column, query) {
  const terms = [];
  for (const match of query.matchAll(RAW_TERM_RE)) {
    const raw = match[1] ?? match[2] ?? "";
    const normalized = normalizeFallbackTerm(raw);
    if (normalized.length > 0 && !terms.includes(normalized)) {
      terms.push(normalized);
    }
  }
  if (terms.length === 0) {
    const fallback = normalizeFallbackTerm(query);
    if (fallback.length > 0) {
      terms.push(fallback);
    }
  }
  return {
    terms,
    where: terms.map(() => `LOWER(${column}) LIKE ? ESCAPE '\\'`),
    args: terms.map((term) => `%${escapeLike(term)}%`)
  };
}
function createFallbackSnippet(content, terms) {
  const haystack = content.toLowerCase();
  let matchIndex = -1;
  let matchLength = 0;
  for (const term of terms) {
    const idx = haystack.indexOf(term);
    if (idx !== -1 && (matchIndex === -1 || idx < matchIndex)) {
      matchIndex = idx;
      matchLength = term.length;
    }
  }
  if (matchIndex === -1) {
    const head = content.trim();
    return head.length <= 80 ? head : `${head.slice(0, 77).trimEnd()}...`;
  }
  const start = Math.max(0, matchIndex - 24);
  const end = Math.min(content.length, matchIndex + Math.max(matchLength, 1) + 40);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < content.length ? "..." : "";
  return `${prefix}${content.slice(start, end).trim()}${suffix}`;
}

// ../_research/lcm-full-20261021/src/store/language-pack.ts
import { existsSync as existsSync2, mkdirSync, readdirSync, readFileSync as readFileSync2, renameSync, statSync, writeFileSync } from "node:fs";
import { join as join3 } from "node:path";

// ../_research/lcm-full-20261021/src/prompts/loader.ts
import { existsSync, readFileSync } from "node:fs";
import { join as join2, dirname as dirname2 } from "node:path";
import { fileURLToPath as fileURLToPath2 } from "node:url";

// scratch/lcm-build/node_modules/js-yaml/dist/js-yaml.mjs
function isNothing(subject) {
  return typeof subject === "undefined" || subject === null;
}
function isObject(subject) {
  return typeof subject === "object" && subject !== null;
}
function toArray(sequence) {
  if (Array.isArray(sequence)) return sequence;
  else if (isNothing(sequence)) return [];
  return [sequence];
}
function extend(target, source) {
  var index, length, key, sourceKeys;
  if (source) {
    sourceKeys = Object.keys(source);
    for (index = 0, length = sourceKeys.length; index < length; index += 1) {
      key = sourceKeys[index];
      target[key] = source[key];
    }
  }
  return target;
}
function repeat(string, count) {
  var result = "", cycle;
  for (cycle = 0; cycle < count; cycle += 1) {
    result += string;
  }
  return result;
}
function isNegativeZero(number) {
  return number === 0 && Number.NEGATIVE_INFINITY === 1 / number;
}
var isNothing_1 = isNothing;
var isObject_1 = isObject;
var toArray_1 = toArray;
var repeat_1 = repeat;
var isNegativeZero_1 = isNegativeZero;
var extend_1 = extend;
var common = {
  isNothing: isNothing_1,
  isObject: isObject_1,
  toArray: toArray_1,
  repeat: repeat_1,
  isNegativeZero: isNegativeZero_1,
  extend: extend_1
};
function formatError(exception2, compact) {
  var where = "", message = exception2.reason || "(unknown reason)";
  if (!exception2.mark) return message;
  if (exception2.mark.name) {
    where += 'in "' + exception2.mark.name + '" ';
  }
  where += "(" + (exception2.mark.line + 1) + ":" + (exception2.mark.column + 1) + ")";
  if (!compact && exception2.mark.snippet) {
    where += "\n\n" + exception2.mark.snippet;
  }
  return message + " " + where;
}
function YAMLException$1(reason, mark) {
  Error.call(this);
  this.name = "YAMLException";
  this.reason = reason;
  this.mark = mark;
  this.message = formatError(this, false);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor);
  } else {
    this.stack = new Error().stack || "";
  }
}
YAMLException$1.prototype = Object.create(Error.prototype);
YAMLException$1.prototype.constructor = YAMLException$1;
YAMLException$1.prototype.toString = function toString(compact) {
  return this.name + ": " + formatError(this, compact);
};
var exception = YAMLException$1;
function getLine(buffer, lineStart, lineEnd, position, maxLineLength) {
  var head = "";
  var tail = "";
  var maxHalfLength = Math.floor(maxLineLength / 2) - 1;
  if (position - lineStart > maxHalfLength) {
    head = " ... ";
    lineStart = position - maxHalfLength + head.length;
  }
  if (lineEnd - position > maxHalfLength) {
    tail = " ...";
    lineEnd = position + maxHalfLength - tail.length;
  }
  return {
    str: head + buffer.slice(lineStart, lineEnd).replace(/\t/g, "\u2192") + tail,
    pos: position - lineStart + head.length
    // relative position
  };
}
function padStart(string, max) {
  return common.repeat(" ", max - string.length) + string;
}
function makeSnippet(mark, options) {
  options = Object.create(options || null);
  if (!mark.buffer) return null;
  if (!options.maxLength) options.maxLength = 79;
  if (typeof options.indent !== "number") options.indent = 1;
  if (typeof options.linesBefore !== "number") options.linesBefore = 3;
  if (typeof options.linesAfter !== "number") options.linesAfter = 2;
  var re = /\r?\n|\r|\0/g;
  var lineStarts = [0];
  var lineEnds = [];
  var match;
  var foundLineNo = -1;
  while (match = re.exec(mark.buffer)) {
    lineEnds.push(match.index);
    lineStarts.push(match.index + match[0].length);
    if (mark.position <= match.index && foundLineNo < 0) {
      foundLineNo = lineStarts.length - 2;
    }
  }
  if (foundLineNo < 0) foundLineNo = lineStarts.length - 1;
  var result = "", i2, line;
  var lineNoLength = Math.min(mark.line + options.linesAfter, lineEnds.length).toString().length;
  var maxLineLength = options.maxLength - (options.indent + lineNoLength + 3);
  for (i2 = 1; i2 <= options.linesBefore; i2++) {
    if (foundLineNo - i2 < 0) break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo - i2],
      lineEnds[foundLineNo - i2],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo - i2]),
      maxLineLength
    );
    result = common.repeat(" ", options.indent) + padStart((mark.line - i2 + 1).toString(), lineNoLength) + " | " + line.str + "\n" + result;
  }
  line = getLine(mark.buffer, lineStarts[foundLineNo], lineEnds[foundLineNo], mark.position, maxLineLength);
  result += common.repeat(" ", options.indent) + padStart((mark.line + 1).toString(), lineNoLength) + " | " + line.str + "\n";
  result += common.repeat("-", options.indent + lineNoLength + 3 + line.pos) + "^\n";
  for (i2 = 1; i2 <= options.linesAfter; i2++) {
    if (foundLineNo + i2 >= lineEnds.length) break;
    line = getLine(
      mark.buffer,
      lineStarts[foundLineNo + i2],
      lineEnds[foundLineNo + i2],
      mark.position - (lineStarts[foundLineNo] - lineStarts[foundLineNo + i2]),
      maxLineLength
    );
    result += common.repeat(" ", options.indent) + padStart((mark.line + i2 + 1).toString(), lineNoLength) + " | " + line.str + "\n";
  }
  return result.replace(/\n$/, "");
}
var snippet = makeSnippet;
var TYPE_CONSTRUCTOR_OPTIONS = [
  "kind",
  "multi",
  "resolve",
  "construct",
  "instanceOf",
  "predicate",
  "represent",
  "representName",
  "defaultStyle",
  "styleAliases"
];
var YAML_NODE_KINDS = [
  "scalar",
  "sequence",
  "mapping"
];
function compileStyleAliases(map2) {
  var result = {};
  if (map2 !== null) {
    Object.keys(map2).forEach(function(style) {
      map2[style].forEach(function(alias) {
        result[String(alias)] = style;
      });
    });
  }
  return result;
}
function Type$1(tag, options) {
  options = options || {};
  Object.keys(options).forEach(function(name) {
    if (TYPE_CONSTRUCTOR_OPTIONS.indexOf(name) === -1) {
      throw new exception('Unknown option "' + name + '" is met in definition of "' + tag + '" YAML type.');
    }
  });
  this.options = options;
  this.tag = tag;
  this.kind = options["kind"] || null;
  this.resolve = options["resolve"] || function() {
    return true;
  };
  this.construct = options["construct"] || function(data) {
    return data;
  };
  this.instanceOf = options["instanceOf"] || null;
  this.predicate = options["predicate"] || null;
  this.represent = options["represent"] || null;
  this.representName = options["representName"] || null;
  this.defaultStyle = options["defaultStyle"] || null;
  this.multi = options["multi"] || false;
  this.styleAliases = compileStyleAliases(options["styleAliases"] || null);
  if (YAML_NODE_KINDS.indexOf(this.kind) === -1) {
    throw new exception('Unknown kind "' + this.kind + '" is specified for "' + tag + '" YAML type.');
  }
}
var type = Type$1;
function compileList(schema2, name) {
  var result = [];
  schema2[name].forEach(function(currentType) {
    var newIndex = result.length;
    result.forEach(function(previousType, previousIndex) {
      if (previousType.tag === currentType.tag && previousType.kind === currentType.kind && previousType.multi === currentType.multi) {
        newIndex = previousIndex;
      }
    });
    result[newIndex] = currentType;
  });
  return result;
}
function compileMap() {
  var result = {
    scalar: {},
    sequence: {},
    mapping: {},
    fallback: {},
    multi: {
      scalar: [],
      sequence: [],
      mapping: [],
      fallback: []
    }
  }, index, length;
  function collectType(type2) {
    if (type2.multi) {
      result.multi[type2.kind].push(type2);
      result.multi["fallback"].push(type2);
    } else {
      result[type2.kind][type2.tag] = result["fallback"][type2.tag] = type2;
    }
  }
  for (index = 0, length = arguments.length; index < length; index += 1) {
    arguments[index].forEach(collectType);
  }
  return result;
}
function Schema$1(definition) {
  return this.extend(definition);
}
Schema$1.prototype.extend = function extend2(definition) {
  var implicit = [];
  var explicit = [];
  if (definition instanceof type) {
    explicit.push(definition);
  } else if (Array.isArray(definition)) {
    explicit = explicit.concat(definition);
  } else if (definition && (Array.isArray(definition.implicit) || Array.isArray(definition.explicit))) {
    if (definition.implicit) implicit = implicit.concat(definition.implicit);
    if (definition.explicit) explicit = explicit.concat(definition.explicit);
  } else {
    throw new exception("Schema.extend argument should be a Type, [ Type ], or a schema definition ({ implicit: [...], explicit: [...] })");
  }
  implicit.forEach(function(type$1) {
    if (!(type$1 instanceof type)) {
      throw new exception("Specified list of YAML types (or a single Type object) contains a non-Type object.");
    }
    if (type$1.loadKind && type$1.loadKind !== "scalar") {
      throw new exception("There is a non-scalar type in the implicit list of a schema. Implicit resolving of such types is not supported.");
    }
    if (type$1.multi) {
      throw new exception("There is a multi type in the implicit list of a schema. Multi tags can only be listed as explicit.");
    }
  });
  explicit.forEach(function(type$1) {
    if (!(type$1 instanceof type)) {
      throw new exception("Specified list of YAML types (or a single Type object) contains a non-Type object.");
    }
  });
  var result = Object.create(Schema$1.prototype);
  result.implicit = (this.implicit || []).concat(implicit);
  result.explicit = (this.explicit || []).concat(explicit);
  result.compiledImplicit = compileList(result, "implicit");
  result.compiledExplicit = compileList(result, "explicit");
  result.compiledTypeMap = compileMap(result.compiledImplicit, result.compiledExplicit);
  return result;
};
var schema = Schema$1;
var str = new type("tag:yaml.org,2002:str", {
  kind: "scalar",
  construct: function(data) {
    return data !== null ? data : "";
  }
});
var seq = new type("tag:yaml.org,2002:seq", {
  kind: "sequence",
  construct: function(data) {
    return data !== null ? data : [];
  }
});
var map = new type("tag:yaml.org,2002:map", {
  kind: "mapping",
  construct: function(data) {
    return data !== null ? data : {};
  }
});
var failsafe = new schema({
  explicit: [
    str,
    seq,
    map
  ]
});
function resolveYamlNull(data) {
  if (data === null) return true;
  var max = data.length;
  return max === 1 && data === "~" || max === 4 && (data === "null" || data === "Null" || data === "NULL");
}
function constructYamlNull() {
  return null;
}
function isNull(object) {
  return object === null;
}
var _null = new type("tag:yaml.org,2002:null", {
  kind: "scalar",
  resolve: resolveYamlNull,
  construct: constructYamlNull,
  predicate: isNull,
  represent: {
    canonical: function() {
      return "~";
    },
    lowercase: function() {
      return "null";
    },
    uppercase: function() {
      return "NULL";
    },
    camelcase: function() {
      return "Null";
    },
    empty: function() {
      return "";
    }
  },
  defaultStyle: "lowercase"
});
function resolveYamlBoolean(data) {
  if (data === null) return false;
  var max = data.length;
  return max === 4 && (data === "true" || data === "True" || data === "TRUE") || max === 5 && (data === "false" || data === "False" || data === "FALSE");
}
function constructYamlBoolean(data) {
  return data === "true" || data === "True" || data === "TRUE";
}
function isBoolean(object) {
  return Object.prototype.toString.call(object) === "[object Boolean]";
}
var bool = new type("tag:yaml.org,2002:bool", {
  kind: "scalar",
  resolve: resolveYamlBoolean,
  construct: constructYamlBoolean,
  predicate: isBoolean,
  represent: {
    lowercase: function(object) {
      return object ? "true" : "false";
    },
    uppercase: function(object) {
      return object ? "TRUE" : "FALSE";
    },
    camelcase: function(object) {
      return object ? "True" : "False";
    }
  },
  defaultStyle: "lowercase"
});
function isHexCode(c) {
  return 48 <= c && c <= 57 || 65 <= c && c <= 70 || 97 <= c && c <= 102;
}
function isOctCode(c) {
  return 48 <= c && c <= 55;
}
function isDecCode(c) {
  return 48 <= c && c <= 57;
}
function resolveYamlInteger(data) {
  if (data === null) return false;
  var max = data.length, index = 0, hasDigits = false, ch;
  if (!max) return false;
  ch = data[index];
  if (ch === "-" || ch === "+") {
    ch = data[++index];
  }
  if (ch === "0") {
    if (index + 1 === max) return true;
    ch = data[++index];
    if (ch === "b") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_") continue;
        if (ch !== "0" && ch !== "1") return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
    if (ch === "x") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_") continue;
        if (!isHexCode(data.charCodeAt(index))) return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
    if (ch === "o") {
      index++;
      for (; index < max; index++) {
        ch = data[index];
        if (ch === "_") continue;
        if (!isOctCode(data.charCodeAt(index))) return false;
        hasDigits = true;
      }
      return hasDigits && ch !== "_";
    }
  }
  if (ch === "_") return false;
  for (; index < max; index++) {
    ch = data[index];
    if (ch === "_") continue;
    if (!isDecCode(data.charCodeAt(index))) {
      return false;
    }
    hasDigits = true;
  }
  if (!hasDigits || ch === "_") return false;
  return true;
}
function constructYamlInteger(data) {
  var value = data, sign = 1, ch;
  if (value.indexOf("_") !== -1) {
    value = value.replace(/_/g, "");
  }
  ch = value[0];
  if (ch === "-" || ch === "+") {
    if (ch === "-") sign = -1;
    value = value.slice(1);
    ch = value[0];
  }
  if (value === "0") return 0;
  if (ch === "0") {
    if (value[1] === "b") return sign * parseInt(value.slice(2), 2);
    if (value[1] === "x") return sign * parseInt(value.slice(2), 16);
    if (value[1] === "o") return sign * parseInt(value.slice(2), 8);
  }
  return sign * parseInt(value, 10);
}
function isInteger(object) {
  return Object.prototype.toString.call(object) === "[object Number]" && (object % 1 === 0 && !common.isNegativeZero(object));
}
var int = new type("tag:yaml.org,2002:int", {
  kind: "scalar",
  resolve: resolveYamlInteger,
  construct: constructYamlInteger,
  predicate: isInteger,
  represent: {
    binary: function(obj) {
      return obj >= 0 ? "0b" + obj.toString(2) : "-0b" + obj.toString(2).slice(1);
    },
    octal: function(obj) {
      return obj >= 0 ? "0o" + obj.toString(8) : "-0o" + obj.toString(8).slice(1);
    },
    decimal: function(obj) {
      return obj.toString(10);
    },
    /* eslint-disable max-len */
    hexadecimal: function(obj) {
      return obj >= 0 ? "0x" + obj.toString(16).toUpperCase() : "-0x" + obj.toString(16).toUpperCase().slice(1);
    }
  },
  defaultStyle: "decimal",
  styleAliases: {
    binary: [2, "bin"],
    octal: [8, "oct"],
    decimal: [10, "dec"],
    hexadecimal: [16, "hex"]
  }
});
var YAML_FLOAT_PATTERN = new RegExp(
  // 2.5e4, 2.5 and integers
  "^(?:[-+]?(?:[0-9][0-9_]*)(?:\\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?|\\.[0-9_]+(?:[eE][-+]?[0-9]+)?|[-+]?\\.(?:inf|Inf|INF)|\\.(?:nan|NaN|NAN))$"
);
function resolveYamlFloat(data) {
  if (data === null) return false;
  if (!YAML_FLOAT_PATTERN.test(data) || // Quick hack to not allow integers end with `_`
  // Probably should update regexp & check speed
  data[data.length - 1] === "_") {
    return false;
  }
  return true;
}
function constructYamlFloat(data) {
  var value, sign;
  value = data.replace(/_/g, "").toLowerCase();
  sign = value[0] === "-" ? -1 : 1;
  if ("+-".indexOf(value[0]) >= 0) {
    value = value.slice(1);
  }
  if (value === ".inf") {
    return sign === 1 ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
  } else if (value === ".nan") {
    return NaN;
  }
  return sign * parseFloat(value, 10);
}
var SCIENTIFIC_WITHOUT_DOT = /^[-+]?[0-9]+e/;
function representYamlFloat(object, style) {
  var res;
  if (isNaN(object)) {
    switch (style) {
      case "lowercase":
        return ".nan";
      case "uppercase":
        return ".NAN";
      case "camelcase":
        return ".NaN";
    }
  } else if (Number.POSITIVE_INFINITY === object) {
    switch (style) {
      case "lowercase":
        return ".inf";
      case "uppercase":
        return ".INF";
      case "camelcase":
        return ".Inf";
    }
  } else if (Number.NEGATIVE_INFINITY === object) {
    switch (style) {
      case "lowercase":
        return "-.inf";
      case "uppercase":
        return "-.INF";
      case "camelcase":
        return "-.Inf";
    }
  } else if (common.isNegativeZero(object)) {
    return "-0.0";
  }
  res = object.toString(10);
  return SCIENTIFIC_WITHOUT_DOT.test(res) ? res.replace("e", ".e") : res;
}
function isFloat(object) {
  return Object.prototype.toString.call(object) === "[object Number]" && (object % 1 !== 0 || common.isNegativeZero(object));
}
var float = new type("tag:yaml.org,2002:float", {
  kind: "scalar",
  resolve: resolveYamlFloat,
  construct: constructYamlFloat,
  predicate: isFloat,
  represent: representYamlFloat,
  defaultStyle: "lowercase"
});
var json = failsafe.extend({
  implicit: [
    _null,
    bool,
    int,
    float
  ]
});
var core = json;
var YAML_DATE_REGEXP = new RegExp(
  "^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])$"
);
var YAML_TIMESTAMP_REGEXP = new RegExp(
  "^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:[Tt]|[ \\t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\\.([0-9]*))?(?:[ \\t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?$"
);
function resolveYamlTimestamp(data) {
  if (data === null) return false;
  if (YAML_DATE_REGEXP.exec(data) !== null) return true;
  if (YAML_TIMESTAMP_REGEXP.exec(data) !== null) return true;
  return false;
}
function constructYamlTimestamp(data) {
  var match, year, month, day, hour, minute, second, fraction = 0, delta = null, tz_hour, tz_minute, date;
  match = YAML_DATE_REGEXP.exec(data);
  if (match === null) match = YAML_TIMESTAMP_REGEXP.exec(data);
  if (match === null) throw new Error("Date resolve error");
  year = +match[1];
  month = +match[2] - 1;
  day = +match[3];
  if (!match[4]) {
    return new Date(Date.UTC(year, month, day));
  }
  hour = +match[4];
  minute = +match[5];
  second = +match[6];
  if (match[7]) {
    fraction = match[7].slice(0, 3);
    while (fraction.length < 3) {
      fraction += "0";
    }
    fraction = +fraction;
  }
  if (match[9]) {
    tz_hour = +match[10];
    tz_minute = +(match[11] || 0);
    delta = (tz_hour * 60 + tz_minute) * 6e4;
    if (match[9] === "-") delta = -delta;
  }
  date = new Date(Date.UTC(year, month, day, hour, minute, second, fraction));
  if (delta) date.setTime(date.getTime() - delta);
  return date;
}
function representYamlTimestamp(object) {
  return object.toISOString();
}
var timestamp = new type("tag:yaml.org,2002:timestamp", {
  kind: "scalar",
  resolve: resolveYamlTimestamp,
  construct: constructYamlTimestamp,
  instanceOf: Date,
  represent: representYamlTimestamp
});
function resolveYamlMerge(data) {
  return data === "<<" || data === null;
}
var merge = new type("tag:yaml.org,2002:merge", {
  kind: "scalar",
  resolve: resolveYamlMerge
});
var BASE64_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r";
function resolveYamlBinary(data) {
  if (data === null) return false;
  var code, idx, bitlen = 0, max = data.length, map2 = BASE64_MAP;
  for (idx = 0; idx < max; idx++) {
    code = map2.indexOf(data.charAt(idx));
    if (code > 64) continue;
    if (code < 0) return false;
    bitlen += 6;
  }
  return bitlen % 8 === 0;
}
function constructYamlBinary(data) {
  var idx, tailbits, input = data.replace(/[\r\n=]/g, ""), max = input.length, map2 = BASE64_MAP, bits = 0, result = [];
  for (idx = 0; idx < max; idx++) {
    if (idx % 4 === 0 && idx) {
      result.push(bits >> 16 & 255);
      result.push(bits >> 8 & 255);
      result.push(bits & 255);
    }
    bits = bits << 6 | map2.indexOf(input.charAt(idx));
  }
  tailbits = max % 4 * 6;
  if (tailbits === 0) {
    result.push(bits >> 16 & 255);
    result.push(bits >> 8 & 255);
    result.push(bits & 255);
  } else if (tailbits === 18) {
    result.push(bits >> 10 & 255);
    result.push(bits >> 2 & 255);
  } else if (tailbits === 12) {
    result.push(bits >> 4 & 255);
  }
  return new Uint8Array(result);
}
function representYamlBinary(object) {
  var result = "", bits = 0, idx, tail, max = object.length, map2 = BASE64_MAP;
  for (idx = 0; idx < max; idx++) {
    if (idx % 3 === 0 && idx) {
      result += map2[bits >> 18 & 63];
      result += map2[bits >> 12 & 63];
      result += map2[bits >> 6 & 63];
      result += map2[bits & 63];
    }
    bits = (bits << 8) + object[idx];
  }
  tail = max % 3;
  if (tail === 0) {
    result += map2[bits >> 18 & 63];
    result += map2[bits >> 12 & 63];
    result += map2[bits >> 6 & 63];
    result += map2[bits & 63];
  } else if (tail === 2) {
    result += map2[bits >> 10 & 63];
    result += map2[bits >> 4 & 63];
    result += map2[bits << 2 & 63];
    result += map2[64];
  } else if (tail === 1) {
    result += map2[bits >> 2 & 63];
    result += map2[bits << 4 & 63];
    result += map2[64];
    result += map2[64];
  }
  return result;
}
function isBinary(obj) {
  return Object.prototype.toString.call(obj) === "[object Uint8Array]";
}
var binary = new type("tag:yaml.org,2002:binary", {
  kind: "scalar",
  resolve: resolveYamlBinary,
  construct: constructYamlBinary,
  predicate: isBinary,
  represent: representYamlBinary
});
var _hasOwnProperty$3 = Object.prototype.hasOwnProperty;
var _toString$2 = Object.prototype.toString;
function resolveYamlOmap(data) {
  if (data === null) return true;
  var objectKeys = [], index, length, pair, pairKey, pairHasKey, object = data;
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    pairHasKey = false;
    if (_toString$2.call(pair) !== "[object Object]") return false;
    for (pairKey in pair) {
      if (_hasOwnProperty$3.call(pair, pairKey)) {
        if (!pairHasKey) pairHasKey = true;
        else return false;
      }
    }
    if (!pairHasKey) return false;
    if (objectKeys.indexOf(pairKey) === -1) objectKeys.push(pairKey);
    else return false;
  }
  return true;
}
function constructYamlOmap(data) {
  return data !== null ? data : [];
}
var omap = new type("tag:yaml.org,2002:omap", {
  kind: "sequence",
  resolve: resolveYamlOmap,
  construct: constructYamlOmap
});
var _toString$1 = Object.prototype.toString;
function resolveYamlPairs(data) {
  if (data === null) return true;
  var index, length, pair, keys, result, object = data;
  result = new Array(object.length);
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    if (_toString$1.call(pair) !== "[object Object]") return false;
    keys = Object.keys(pair);
    if (keys.length !== 1) return false;
    result[index] = [keys[0], pair[keys[0]]];
  }
  return true;
}
function constructYamlPairs(data) {
  if (data === null) return [];
  var index, length, pair, keys, result, object = data;
  result = new Array(object.length);
  for (index = 0, length = object.length; index < length; index += 1) {
    pair = object[index];
    keys = Object.keys(pair);
    result[index] = [keys[0], pair[keys[0]]];
  }
  return result;
}
var pairs = new type("tag:yaml.org,2002:pairs", {
  kind: "sequence",
  resolve: resolveYamlPairs,
  construct: constructYamlPairs
});
var _hasOwnProperty$2 = Object.prototype.hasOwnProperty;
function resolveYamlSet(data) {
  if (data === null) return true;
  var key, object = data;
  for (key in object) {
    if (_hasOwnProperty$2.call(object, key)) {
      if (object[key] !== null) return false;
    }
  }
  return true;
}
function constructYamlSet(data) {
  return data !== null ? data : {};
}
var set = new type("tag:yaml.org,2002:set", {
  kind: "mapping",
  resolve: resolveYamlSet,
  construct: constructYamlSet
});
var _default = core.extend({
  implicit: [
    timestamp,
    merge
  ],
  explicit: [
    binary,
    omap,
    pairs,
    set
  ]
});
var _hasOwnProperty$1 = Object.prototype.hasOwnProperty;
var CONTEXT_FLOW_IN = 1;
var CONTEXT_FLOW_OUT = 2;
var CONTEXT_BLOCK_IN = 3;
var CONTEXT_BLOCK_OUT = 4;
var CHOMPING_CLIP = 1;
var CHOMPING_STRIP = 2;
var CHOMPING_KEEP = 3;
var PATTERN_NON_PRINTABLE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x84\x86-\x9F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;
var PATTERN_NON_ASCII_LINE_BREAKS = /[\x85\u2028\u2029]/;
var PATTERN_FLOW_INDICATORS = /[,\[\]\{\}]/;
var PATTERN_TAG_HANDLE = /^(?:!|!!|![a-z\-]+!)$/i;
var PATTERN_TAG_URI = /^(?:!|[^,\[\]\{\}])(?:%[0-9a-f]{2}|[0-9a-z\-#;\/\?:@&=\+\$,_\.!~\*'\(\)\[\]])*$/i;
function _class(obj) {
  return Object.prototype.toString.call(obj);
}
function is_EOL(c) {
  return c === 10 || c === 13;
}
function is_WHITE_SPACE(c) {
  return c === 9 || c === 32;
}
function is_WS_OR_EOL(c) {
  return c === 9 || c === 32 || c === 10 || c === 13;
}
function is_FLOW_INDICATOR(c) {
  return c === 44 || c === 91 || c === 93 || c === 123 || c === 125;
}
function fromHexCode(c) {
  var lc;
  if (48 <= c && c <= 57) {
    return c - 48;
  }
  lc = c | 32;
  if (97 <= lc && lc <= 102) {
    return lc - 97 + 10;
  }
  return -1;
}
function escapedHexLen(c) {
  if (c === 120) {
    return 2;
  }
  if (c === 117) {
    return 4;
  }
  if (c === 85) {
    return 8;
  }
  return 0;
}
function fromDecimalCode(c) {
  if (48 <= c && c <= 57) {
    return c - 48;
  }
  return -1;
}
function simpleEscapeSequence(c) {
  return c === 48 ? "\0" : c === 97 ? "\x07" : c === 98 ? "\b" : c === 116 ? "	" : c === 9 ? "	" : c === 110 ? "\n" : c === 118 ? "\v" : c === 102 ? "\f" : c === 114 ? "\r" : c === 101 ? "\x1B" : c === 32 ? " " : c === 34 ? '"' : c === 47 ? "/" : c === 92 ? "\\" : c === 78 ? "\x85" : c === 95 ? "\xA0" : c === 76 ? "\u2028" : c === 80 ? "\u2029" : "";
}
function charFromCodepoint(c) {
  if (c <= 65535) {
    return String.fromCharCode(c);
  }
  return String.fromCharCode(
    (c - 65536 >> 10) + 55296,
    (c - 65536 & 1023) + 56320
  );
}
function setProperty(object, key, value) {
  if (key === "__proto__") {
    Object.defineProperty(object, key, {
      configurable: true,
      enumerable: true,
      writable: true,
      value
    });
  } else {
    object[key] = value;
  }
}
var simpleEscapeCheck = new Array(256);
var simpleEscapeMap = new Array(256);
for (i = 0; i < 256; i++) {
  simpleEscapeCheck[i] = simpleEscapeSequence(i) ? 1 : 0;
  simpleEscapeMap[i] = simpleEscapeSequence(i);
}
var i;
function State$1(input, options) {
  this.input = input;
  this.filename = options["filename"] || null;
  this.schema = options["schema"] || _default;
  this.onWarning = options["onWarning"] || null;
  this.legacy = options["legacy"] || false;
  this.json = options["json"] || false;
  this.listener = options["listener"] || null;
  this.implicitTypes = this.schema.compiledImplicit;
  this.typeMap = this.schema.compiledTypeMap;
  this.length = input.length;
  this.position = 0;
  this.line = 0;
  this.lineStart = 0;
  this.lineIndent = 0;
  this.firstTabInLine = -1;
  this.documents = [];
}
function generateError(state, message) {
  var mark = {
    name: state.filename,
    buffer: state.input.slice(0, -1),
    // omit trailing \0
    position: state.position,
    line: state.line,
    column: state.position - state.lineStart
  };
  mark.snippet = snippet(mark);
  return new exception(message, mark);
}
function throwError(state, message) {
  throw generateError(state, message);
}
function throwWarning(state, message) {
  if (state.onWarning) {
    state.onWarning.call(null, generateError(state, message));
  }
}
var directiveHandlers = {
  YAML: function handleYamlDirective(state, name, args) {
    var match, major, minor;
    if (state.version !== null) {
      throwError(state, "duplication of %YAML directive");
    }
    if (args.length !== 1) {
      throwError(state, "YAML directive accepts exactly one argument");
    }
    match = /^([0-9]+)\.([0-9]+)$/.exec(args[0]);
    if (match === null) {
      throwError(state, "ill-formed argument of the YAML directive");
    }
    major = parseInt(match[1], 10);
    minor = parseInt(match[2], 10);
    if (major !== 1) {
      throwError(state, "unacceptable YAML version of the document");
    }
    state.version = args[0];
    state.checkLineBreaks = minor < 2;
    if (minor !== 1 && minor !== 2) {
      throwWarning(state, "unsupported YAML version of the document");
    }
  },
  TAG: function handleTagDirective(state, name, args) {
    var handle, prefix;
    if (args.length !== 2) {
      throwError(state, "TAG directive accepts exactly two arguments");
    }
    handle = args[0];
    prefix = args[1];
    if (!PATTERN_TAG_HANDLE.test(handle)) {
      throwError(state, "ill-formed tag handle (first argument) of the TAG directive");
    }
    if (_hasOwnProperty$1.call(state.tagMap, handle)) {
      throwError(state, 'there is a previously declared suffix for "' + handle + '" tag handle');
    }
    if (!PATTERN_TAG_URI.test(prefix)) {
      throwError(state, "ill-formed tag prefix (second argument) of the TAG directive");
    }
    try {
      prefix = decodeURIComponent(prefix);
    } catch (err) {
      throwError(state, "tag prefix is malformed: " + prefix);
    }
    state.tagMap[handle] = prefix;
  }
};
function captureSegment(state, start, end, checkJson) {
  var _position, _length, _character, _result;
  if (start < end) {
    _result = state.input.slice(start, end);
    if (checkJson) {
      for (_position = 0, _length = _result.length; _position < _length; _position += 1) {
        _character = _result.charCodeAt(_position);
        if (!(_character === 9 || 32 <= _character && _character <= 1114111)) {
          throwError(state, "expected valid JSON character");
        }
      }
    } else if (PATTERN_NON_PRINTABLE.test(_result)) {
      throwError(state, "the stream contains non-printable characters");
    }
    state.result += _result;
  }
}
function mergeMappings(state, destination, source, overridableKeys) {
  var sourceKeys, key, index, quantity;
  if (!common.isObject(source)) {
    throwError(state, "cannot merge mappings; the provided source object is unacceptable");
  }
  sourceKeys = Object.keys(source);
  for (index = 0, quantity = sourceKeys.length; index < quantity; index += 1) {
    key = sourceKeys[index];
    if (!_hasOwnProperty$1.call(destination, key)) {
      setProperty(destination, key, source[key]);
      overridableKeys[key] = true;
    }
  }
}
function storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, startLine, startLineStart, startPos) {
  var index, quantity;
  if (Array.isArray(keyNode)) {
    keyNode = Array.prototype.slice.call(keyNode);
    for (index = 0, quantity = keyNode.length; index < quantity; index += 1) {
      if (Array.isArray(keyNode[index])) {
        throwError(state, "nested arrays are not supported inside keys");
      }
      if (typeof keyNode === "object" && _class(keyNode[index]) === "[object Object]") {
        keyNode[index] = "[object Object]";
      }
    }
  }
  if (typeof keyNode === "object" && _class(keyNode) === "[object Object]") {
    keyNode = "[object Object]";
  }
  keyNode = String(keyNode);
  if (_result === null) {
    _result = {};
  }
  if (keyTag === "tag:yaml.org,2002:merge") {
    if (Array.isArray(valueNode)) {
      for (index = 0, quantity = valueNode.length; index < quantity; index += 1) {
        mergeMappings(state, _result, valueNode[index], overridableKeys);
      }
    } else {
      mergeMappings(state, _result, valueNode, overridableKeys);
    }
  } else {
    if (!state.json && !_hasOwnProperty$1.call(overridableKeys, keyNode) && _hasOwnProperty$1.call(_result, keyNode)) {
      state.line = startLine || state.line;
      state.lineStart = startLineStart || state.lineStart;
      state.position = startPos || state.position;
      throwError(state, "duplicated mapping key");
    }
    setProperty(_result, keyNode, valueNode);
    delete overridableKeys[keyNode];
  }
  return _result;
}
function readLineBreak(state) {
  var ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 10) {
    state.position++;
  } else if (ch === 13) {
    state.position++;
    if (state.input.charCodeAt(state.position) === 10) {
      state.position++;
    }
  } else {
    throwError(state, "a line break is expected");
  }
  state.line += 1;
  state.lineStart = state.position;
  state.firstTabInLine = -1;
}
function skipSeparationSpace(state, allowComments, checkIndent) {
  var lineBreaks = 0, ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    while (is_WHITE_SPACE(ch)) {
      if (ch === 9 && state.firstTabInLine === -1) {
        state.firstTabInLine = state.position;
      }
      ch = state.input.charCodeAt(++state.position);
    }
    if (allowComments && ch === 35) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (ch !== 10 && ch !== 13 && ch !== 0);
    }
    if (is_EOL(ch)) {
      readLineBreak(state);
      ch = state.input.charCodeAt(state.position);
      lineBreaks++;
      state.lineIndent = 0;
      while (ch === 32) {
        state.lineIndent++;
        ch = state.input.charCodeAt(++state.position);
      }
    } else {
      break;
    }
  }
  if (checkIndent !== -1 && lineBreaks !== 0 && state.lineIndent < checkIndent) {
    throwWarning(state, "deficient indentation");
  }
  return lineBreaks;
}
function testDocumentSeparator(state) {
  var _position = state.position, ch;
  ch = state.input.charCodeAt(_position);
  if ((ch === 45 || ch === 46) && ch === state.input.charCodeAt(_position + 1) && ch === state.input.charCodeAt(_position + 2)) {
    _position += 3;
    ch = state.input.charCodeAt(_position);
    if (ch === 0 || is_WS_OR_EOL(ch)) {
      return true;
    }
  }
  return false;
}
function writeFoldedLines(state, count) {
  if (count === 1) {
    state.result += " ";
  } else if (count > 1) {
    state.result += common.repeat("\n", count - 1);
  }
}
function readPlainScalar(state, nodeIndent, withinFlowCollection) {
  var preceding, following, captureStart, captureEnd, hasPendingContent, _line, _lineStart, _lineIndent, _kind = state.kind, _result = state.result, ch;
  ch = state.input.charCodeAt(state.position);
  if (is_WS_OR_EOL(ch) || is_FLOW_INDICATOR(ch) || ch === 35 || ch === 38 || ch === 42 || ch === 33 || ch === 124 || ch === 62 || ch === 39 || ch === 34 || ch === 37 || ch === 64 || ch === 96) {
    return false;
  }
  if (ch === 63 || ch === 45) {
    following = state.input.charCodeAt(state.position + 1);
    if (is_WS_OR_EOL(following) || withinFlowCollection && is_FLOW_INDICATOR(following)) {
      return false;
    }
  }
  state.kind = "scalar";
  state.result = "";
  captureStart = captureEnd = state.position;
  hasPendingContent = false;
  while (ch !== 0) {
    if (ch === 58) {
      following = state.input.charCodeAt(state.position + 1);
      if (is_WS_OR_EOL(following) || withinFlowCollection && is_FLOW_INDICATOR(following)) {
        break;
      }
    } else if (ch === 35) {
      preceding = state.input.charCodeAt(state.position - 1);
      if (is_WS_OR_EOL(preceding)) {
        break;
      }
    } else if (state.position === state.lineStart && testDocumentSeparator(state) || withinFlowCollection && is_FLOW_INDICATOR(ch)) {
      break;
    } else if (is_EOL(ch)) {
      _line = state.line;
      _lineStart = state.lineStart;
      _lineIndent = state.lineIndent;
      skipSeparationSpace(state, false, -1);
      if (state.lineIndent >= nodeIndent) {
        hasPendingContent = true;
        ch = state.input.charCodeAt(state.position);
        continue;
      } else {
        state.position = captureEnd;
        state.line = _line;
        state.lineStart = _lineStart;
        state.lineIndent = _lineIndent;
        break;
      }
    }
    if (hasPendingContent) {
      captureSegment(state, captureStart, captureEnd, false);
      writeFoldedLines(state, state.line - _line);
      captureStart = captureEnd = state.position;
      hasPendingContent = false;
    }
    if (!is_WHITE_SPACE(ch)) {
      captureEnd = state.position + 1;
    }
    ch = state.input.charCodeAt(++state.position);
  }
  captureSegment(state, captureStart, captureEnd, false);
  if (state.result) {
    return true;
  }
  state.kind = _kind;
  state.result = _result;
  return false;
}
function readSingleQuotedScalar(state, nodeIndent) {
  var ch, captureStart, captureEnd;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 39) {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  state.position++;
  captureStart = captureEnd = state.position;
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 39) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);
      if (ch === 39) {
        captureStart = state.position;
        state.position++;
        captureEnd = state.position;
      } else {
        return true;
      }
    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, "unexpected end of the document within a single quoted scalar");
    } else {
      state.position++;
      captureEnd = state.position;
    }
  }
  throwError(state, "unexpected end of the stream within a single quoted scalar");
}
function readDoubleQuotedScalar(state, nodeIndent) {
  var captureStart, captureEnd, hexLength, hexResult, tmp, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 34) {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  state.position++;
  captureStart = captureEnd = state.position;
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    if (ch === 34) {
      captureSegment(state, captureStart, state.position, true);
      state.position++;
      return true;
    } else if (ch === 92) {
      captureSegment(state, captureStart, state.position, true);
      ch = state.input.charCodeAt(++state.position);
      if (is_EOL(ch)) {
        skipSeparationSpace(state, false, nodeIndent);
      } else if (ch < 256 && simpleEscapeCheck[ch]) {
        state.result += simpleEscapeMap[ch];
        state.position++;
      } else if ((tmp = escapedHexLen(ch)) > 0) {
        hexLength = tmp;
        hexResult = 0;
        for (; hexLength > 0; hexLength--) {
          ch = state.input.charCodeAt(++state.position);
          if ((tmp = fromHexCode(ch)) >= 0) {
            hexResult = (hexResult << 4) + tmp;
          } else {
            throwError(state, "expected hexadecimal character");
          }
        }
        state.result += charFromCodepoint(hexResult);
        state.position++;
      } else {
        throwError(state, "unknown escape sequence");
      }
      captureStart = captureEnd = state.position;
    } else if (is_EOL(ch)) {
      captureSegment(state, captureStart, captureEnd, true);
      writeFoldedLines(state, skipSeparationSpace(state, false, nodeIndent));
      captureStart = captureEnd = state.position;
    } else if (state.position === state.lineStart && testDocumentSeparator(state)) {
      throwError(state, "unexpected end of the document within a double quoted scalar");
    } else {
      state.position++;
      captureEnd = state.position;
    }
  }
  throwError(state, "unexpected end of the stream within a double quoted scalar");
}
function readFlowCollection(state, nodeIndent) {
  var readNext = true, _line, _lineStart, _pos, _tag = state.tag, _result, _anchor = state.anchor, following, terminator, isPair, isExplicitPair, isMapping, overridableKeys = /* @__PURE__ */ Object.create(null), keyNode, keyTag, valueNode, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 91) {
    terminator = 93;
    isMapping = false;
    _result = [];
  } else if (ch === 123) {
    terminator = 125;
    isMapping = true;
    _result = {};
  } else {
    return false;
  }
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(++state.position);
  while (ch !== 0) {
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if (ch === terminator) {
      state.position++;
      state.tag = _tag;
      state.anchor = _anchor;
      state.kind = isMapping ? "mapping" : "sequence";
      state.result = _result;
      return true;
    } else if (!readNext) {
      throwError(state, "missed comma between flow collection entries");
    } else if (ch === 44) {
      throwError(state, "expected the node content, but found ','");
    }
    keyTag = keyNode = valueNode = null;
    isPair = isExplicitPair = false;
    if (ch === 63) {
      following = state.input.charCodeAt(state.position + 1);
      if (is_WS_OR_EOL(following)) {
        isPair = isExplicitPair = true;
        state.position++;
        skipSeparationSpace(state, true, nodeIndent);
      }
    }
    _line = state.line;
    _lineStart = state.lineStart;
    _pos = state.position;
    composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
    keyTag = state.tag;
    keyNode = state.result;
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if ((isExplicitPair || state.line === _line) && ch === 58) {
      isPair = true;
      ch = state.input.charCodeAt(++state.position);
      skipSeparationSpace(state, true, nodeIndent);
      composeNode(state, nodeIndent, CONTEXT_FLOW_IN, false, true);
      valueNode = state.result;
    }
    if (isMapping) {
      storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos);
    } else if (isPair) {
      _result.push(storeMappingPair(state, null, overridableKeys, keyTag, keyNode, valueNode, _line, _lineStart, _pos));
    } else {
      _result.push(keyNode);
    }
    skipSeparationSpace(state, true, nodeIndent);
    ch = state.input.charCodeAt(state.position);
    if (ch === 44) {
      readNext = true;
      ch = state.input.charCodeAt(++state.position);
    } else {
      readNext = false;
    }
  }
  throwError(state, "unexpected end of the stream within a flow collection");
}
function readBlockScalar(state, nodeIndent) {
  var captureStart, folding, chomping = CHOMPING_CLIP, didReadContent = false, detectedIndent = false, textIndent = nodeIndent, emptyLines = 0, atMoreIndented = false, tmp, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch === 124) {
    folding = false;
  } else if (ch === 62) {
    folding = true;
  } else {
    return false;
  }
  state.kind = "scalar";
  state.result = "";
  while (ch !== 0) {
    ch = state.input.charCodeAt(++state.position);
    if (ch === 43 || ch === 45) {
      if (CHOMPING_CLIP === chomping) {
        chomping = ch === 43 ? CHOMPING_KEEP : CHOMPING_STRIP;
      } else {
        throwError(state, "repeat of a chomping mode identifier");
      }
    } else if ((tmp = fromDecimalCode(ch)) >= 0) {
      if (tmp === 0) {
        throwError(state, "bad explicit indentation width of a block scalar; it cannot be less than one");
      } else if (!detectedIndent) {
        textIndent = nodeIndent + tmp - 1;
        detectedIndent = true;
      } else {
        throwError(state, "repeat of an indentation width identifier");
      }
    } else {
      break;
    }
  }
  if (is_WHITE_SPACE(ch)) {
    do {
      ch = state.input.charCodeAt(++state.position);
    } while (is_WHITE_SPACE(ch));
    if (ch === 35) {
      do {
        ch = state.input.charCodeAt(++state.position);
      } while (!is_EOL(ch) && ch !== 0);
    }
  }
  while (ch !== 0) {
    readLineBreak(state);
    state.lineIndent = 0;
    ch = state.input.charCodeAt(state.position);
    while ((!detectedIndent || state.lineIndent < textIndent) && ch === 32) {
      state.lineIndent++;
      ch = state.input.charCodeAt(++state.position);
    }
    if (!detectedIndent && state.lineIndent > textIndent) {
      textIndent = state.lineIndent;
    }
    if (is_EOL(ch)) {
      emptyLines++;
      continue;
    }
    if (state.lineIndent < textIndent) {
      if (chomping === CHOMPING_KEEP) {
        state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
      } else if (chomping === CHOMPING_CLIP) {
        if (didReadContent) {
          state.result += "\n";
        }
      }
      break;
    }
    if (folding) {
      if (is_WHITE_SPACE(ch)) {
        atMoreIndented = true;
        state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
      } else if (atMoreIndented) {
        atMoreIndented = false;
        state.result += common.repeat("\n", emptyLines + 1);
      } else if (emptyLines === 0) {
        if (didReadContent) {
          state.result += " ";
        }
      } else {
        state.result += common.repeat("\n", emptyLines);
      }
    } else {
      state.result += common.repeat("\n", didReadContent ? 1 + emptyLines : emptyLines);
    }
    didReadContent = true;
    detectedIndent = true;
    emptyLines = 0;
    captureStart = state.position;
    while (!is_EOL(ch) && ch !== 0) {
      ch = state.input.charCodeAt(++state.position);
    }
    captureSegment(state, captureStart, state.position, false);
  }
  return true;
}
function readBlockSequence(state, nodeIndent) {
  var _line, _tag = state.tag, _anchor = state.anchor, _result = [], following, detected = false, ch;
  if (state.firstTabInLine !== -1) return false;
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    if (state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, "tab characters must not be used in indentation");
    }
    if (ch !== 45) {
      break;
    }
    following = state.input.charCodeAt(state.position + 1);
    if (!is_WS_OR_EOL(following)) {
      break;
    }
    detected = true;
    state.position++;
    if (skipSeparationSpace(state, true, -1)) {
      if (state.lineIndent <= nodeIndent) {
        _result.push(null);
        ch = state.input.charCodeAt(state.position);
        continue;
      }
    }
    _line = state.line;
    composeNode(state, nodeIndent, CONTEXT_BLOCK_IN, false, true);
    _result.push(state.result);
    skipSeparationSpace(state, true, -1);
    ch = state.input.charCodeAt(state.position);
    if ((state.line === _line || state.lineIndent > nodeIndent) && ch !== 0) {
      throwError(state, "bad indentation of a sequence entry");
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = "sequence";
    state.result = _result;
    return true;
  }
  return false;
}
function readBlockMapping(state, nodeIndent, flowIndent) {
  var following, allowCompact, _line, _keyLine, _keyLineStart, _keyPos, _tag = state.tag, _anchor = state.anchor, _result = {}, overridableKeys = /* @__PURE__ */ Object.create(null), keyTag = null, keyNode = null, valueNode = null, atExplicitKey = false, detected = false, ch;
  if (state.firstTabInLine !== -1) return false;
  if (state.anchor !== null) {
    state.anchorMap[state.anchor] = _result;
  }
  ch = state.input.charCodeAt(state.position);
  while (ch !== 0) {
    if (!atExplicitKey && state.firstTabInLine !== -1) {
      state.position = state.firstTabInLine;
      throwError(state, "tab characters must not be used in indentation");
    }
    following = state.input.charCodeAt(state.position + 1);
    _line = state.line;
    if ((ch === 63 || ch === 58) && is_WS_OR_EOL(following)) {
      if (ch === 63) {
        if (atExplicitKey) {
          storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
          keyTag = keyNode = valueNode = null;
        }
        detected = true;
        atExplicitKey = true;
        allowCompact = true;
      } else if (atExplicitKey) {
        atExplicitKey = false;
        allowCompact = true;
      } else {
        throwError(state, "incomplete explicit mapping pair; a key node is missed; or followed by a non-tabulated empty line");
      }
      state.position += 1;
      ch = following;
    } else {
      _keyLine = state.line;
      _keyLineStart = state.lineStart;
      _keyPos = state.position;
      if (!composeNode(state, flowIndent, CONTEXT_FLOW_OUT, false, true)) {
        break;
      }
      if (state.line === _line) {
        ch = state.input.charCodeAt(state.position);
        while (is_WHITE_SPACE(ch)) {
          ch = state.input.charCodeAt(++state.position);
        }
        if (ch === 58) {
          ch = state.input.charCodeAt(++state.position);
          if (!is_WS_OR_EOL(ch)) {
            throwError(state, "a whitespace character is expected after the key-value separator within a block mapping");
          }
          if (atExplicitKey) {
            storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
            keyTag = keyNode = valueNode = null;
          }
          detected = true;
          atExplicitKey = false;
          allowCompact = false;
          keyTag = state.tag;
          keyNode = state.result;
        } else if (detected) {
          throwError(state, "can not read an implicit mapping pair; a colon is missed");
        } else {
          state.tag = _tag;
          state.anchor = _anchor;
          return true;
        }
      } else if (detected) {
        throwError(state, "can not read a block mapping entry; a multiline key may not be an implicit key");
      } else {
        state.tag = _tag;
        state.anchor = _anchor;
        return true;
      }
    }
    if (state.line === _line || state.lineIndent > nodeIndent) {
      if (atExplicitKey) {
        _keyLine = state.line;
        _keyLineStart = state.lineStart;
        _keyPos = state.position;
      }
      if (composeNode(state, nodeIndent, CONTEXT_BLOCK_OUT, true, allowCompact)) {
        if (atExplicitKey) {
          keyNode = state.result;
        } else {
          valueNode = state.result;
        }
      }
      if (!atExplicitKey) {
        storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, valueNode, _keyLine, _keyLineStart, _keyPos);
        keyTag = keyNode = valueNode = null;
      }
      skipSeparationSpace(state, true, -1);
      ch = state.input.charCodeAt(state.position);
    }
    if ((state.line === _line || state.lineIndent > nodeIndent) && ch !== 0) {
      throwError(state, "bad indentation of a mapping entry");
    } else if (state.lineIndent < nodeIndent) {
      break;
    }
  }
  if (atExplicitKey) {
    storeMappingPair(state, _result, overridableKeys, keyTag, keyNode, null, _keyLine, _keyLineStart, _keyPos);
  }
  if (detected) {
    state.tag = _tag;
    state.anchor = _anchor;
    state.kind = "mapping";
    state.result = _result;
  }
  return detected;
}
function readTagProperty(state) {
  var _position, isVerbatim = false, isNamed = false, tagHandle, tagName, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 33) return false;
  if (state.tag !== null) {
    throwError(state, "duplication of a tag property");
  }
  ch = state.input.charCodeAt(++state.position);
  if (ch === 60) {
    isVerbatim = true;
    ch = state.input.charCodeAt(++state.position);
  } else if (ch === 33) {
    isNamed = true;
    tagHandle = "!!";
    ch = state.input.charCodeAt(++state.position);
  } else {
    tagHandle = "!";
  }
  _position = state.position;
  if (isVerbatim) {
    do {
      ch = state.input.charCodeAt(++state.position);
    } while (ch !== 0 && ch !== 62);
    if (state.position < state.length) {
      tagName = state.input.slice(_position, state.position);
      ch = state.input.charCodeAt(++state.position);
    } else {
      throwError(state, "unexpected end of the stream within a verbatim tag");
    }
  } else {
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      if (ch === 33) {
        if (!isNamed) {
          tagHandle = state.input.slice(_position - 1, state.position + 1);
          if (!PATTERN_TAG_HANDLE.test(tagHandle)) {
            throwError(state, "named tag handle cannot contain such characters");
          }
          isNamed = true;
          _position = state.position + 1;
        } else {
          throwError(state, "tag suffix cannot contain exclamation marks");
        }
      }
      ch = state.input.charCodeAt(++state.position);
    }
    tagName = state.input.slice(_position, state.position);
    if (PATTERN_FLOW_INDICATORS.test(tagName)) {
      throwError(state, "tag suffix cannot contain flow indicator characters");
    }
  }
  if (tagName && !PATTERN_TAG_URI.test(tagName)) {
    throwError(state, "tag name cannot contain such characters: " + tagName);
  }
  try {
    tagName = decodeURIComponent(tagName);
  } catch (err) {
    throwError(state, "tag name is malformed: " + tagName);
  }
  if (isVerbatim) {
    state.tag = tagName;
  } else if (_hasOwnProperty$1.call(state.tagMap, tagHandle)) {
    state.tag = state.tagMap[tagHandle] + tagName;
  } else if (tagHandle === "!") {
    state.tag = "!" + tagName;
  } else if (tagHandle === "!!") {
    state.tag = "tag:yaml.org,2002:" + tagName;
  } else {
    throwError(state, 'undeclared tag handle "' + tagHandle + '"');
  }
  return true;
}
function readAnchorProperty(state) {
  var _position, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 38) return false;
  if (state.anchor !== null) {
    throwError(state, "duplication of an anchor property");
  }
  ch = state.input.charCodeAt(++state.position);
  _position = state.position;
  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }
  if (state.position === _position) {
    throwError(state, "name of an anchor node must contain at least one character");
  }
  state.anchor = state.input.slice(_position, state.position);
  return true;
}
function readAlias(state) {
  var _position, alias, ch;
  ch = state.input.charCodeAt(state.position);
  if (ch !== 42) return false;
  ch = state.input.charCodeAt(++state.position);
  _position = state.position;
  while (ch !== 0 && !is_WS_OR_EOL(ch) && !is_FLOW_INDICATOR(ch)) {
    ch = state.input.charCodeAt(++state.position);
  }
  if (state.position === _position) {
    throwError(state, "name of an alias node must contain at least one character");
  }
  alias = state.input.slice(_position, state.position);
  if (!_hasOwnProperty$1.call(state.anchorMap, alias)) {
    throwError(state, 'unidentified alias "' + alias + '"');
  }
  state.result = state.anchorMap[alias];
  skipSeparationSpace(state, true, -1);
  return true;
}
function composeNode(state, parentIndent, nodeContext, allowToSeek, allowCompact) {
  var allowBlockStyles, allowBlockScalars, allowBlockCollections, indentStatus = 1, atNewLine = false, hasContent = false, typeIndex, typeQuantity, typeList, type2, flowIndent, blockIndent;
  if (state.listener !== null) {
    state.listener("open", state);
  }
  state.tag = null;
  state.anchor = null;
  state.kind = null;
  state.result = null;
  allowBlockStyles = allowBlockScalars = allowBlockCollections = CONTEXT_BLOCK_OUT === nodeContext || CONTEXT_BLOCK_IN === nodeContext;
  if (allowToSeek) {
    if (skipSeparationSpace(state, true, -1)) {
      atNewLine = true;
      if (state.lineIndent > parentIndent) {
        indentStatus = 1;
      } else if (state.lineIndent === parentIndent) {
        indentStatus = 0;
      } else if (state.lineIndent < parentIndent) {
        indentStatus = -1;
      }
    }
  }
  if (indentStatus === 1) {
    while (readTagProperty(state) || readAnchorProperty(state)) {
      if (skipSeparationSpace(state, true, -1)) {
        atNewLine = true;
        allowBlockCollections = allowBlockStyles;
        if (state.lineIndent > parentIndent) {
          indentStatus = 1;
        } else if (state.lineIndent === parentIndent) {
          indentStatus = 0;
        } else if (state.lineIndent < parentIndent) {
          indentStatus = -1;
        }
      } else {
        allowBlockCollections = false;
      }
    }
  }
  if (allowBlockCollections) {
    allowBlockCollections = atNewLine || allowCompact;
  }
  if (indentStatus === 1 || CONTEXT_BLOCK_OUT === nodeContext) {
    if (CONTEXT_FLOW_IN === nodeContext || CONTEXT_FLOW_OUT === nodeContext) {
      flowIndent = parentIndent;
    } else {
      flowIndent = parentIndent + 1;
    }
    blockIndent = state.position - state.lineStart;
    if (indentStatus === 1) {
      if (allowBlockCollections && (readBlockSequence(state, blockIndent) || readBlockMapping(state, blockIndent, flowIndent)) || readFlowCollection(state, flowIndent)) {
        hasContent = true;
      } else {
        if (allowBlockScalars && readBlockScalar(state, flowIndent) || readSingleQuotedScalar(state, flowIndent) || readDoubleQuotedScalar(state, flowIndent)) {
          hasContent = true;
        } else if (readAlias(state)) {
          hasContent = true;
          if (state.tag !== null || state.anchor !== null) {
            throwError(state, "alias node should not have any properties");
          }
        } else if (readPlainScalar(state, flowIndent, CONTEXT_FLOW_IN === nodeContext)) {
          hasContent = true;
          if (state.tag === null) {
            state.tag = "?";
          }
        }
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
      }
    } else if (indentStatus === 0) {
      hasContent = allowBlockCollections && readBlockSequence(state, blockIndent);
    }
  }
  if (state.tag === null) {
    if (state.anchor !== null) {
      state.anchorMap[state.anchor] = state.result;
    }
  } else if (state.tag === "?") {
    if (state.result !== null && state.kind !== "scalar") {
      throwError(state, 'unacceptable node kind for !<?> tag; it should be "scalar", not "' + state.kind + '"');
    }
    for (typeIndex = 0, typeQuantity = state.implicitTypes.length; typeIndex < typeQuantity; typeIndex += 1) {
      type2 = state.implicitTypes[typeIndex];
      if (type2.resolve(state.result)) {
        state.result = type2.construct(state.result);
        state.tag = type2.tag;
        if (state.anchor !== null) {
          state.anchorMap[state.anchor] = state.result;
        }
        break;
      }
    }
  } else if (state.tag !== "!") {
    if (_hasOwnProperty$1.call(state.typeMap[state.kind || "fallback"], state.tag)) {
      type2 = state.typeMap[state.kind || "fallback"][state.tag];
    } else {
      type2 = null;
      typeList = state.typeMap.multi[state.kind || "fallback"];
      for (typeIndex = 0, typeQuantity = typeList.length; typeIndex < typeQuantity; typeIndex += 1) {
        if (state.tag.slice(0, typeList[typeIndex].tag.length) === typeList[typeIndex].tag) {
          type2 = typeList[typeIndex];
          break;
        }
      }
    }
    if (!type2) {
      throwError(state, "unknown tag !<" + state.tag + ">");
    }
    if (state.result !== null && type2.kind !== state.kind) {
      throwError(state, "unacceptable node kind for !<" + state.tag + '> tag; it should be "' + type2.kind + '", not "' + state.kind + '"');
    }
    if (!type2.resolve(state.result, state.tag)) {
      throwError(state, "cannot resolve a node with !<" + state.tag + "> explicit tag");
    } else {
      state.result = type2.construct(state.result, state.tag);
      if (state.anchor !== null) {
        state.anchorMap[state.anchor] = state.result;
      }
    }
  }
  if (state.listener !== null) {
    state.listener("close", state);
  }
  return state.tag !== null || state.anchor !== null || hasContent;
}
function readDocument(state) {
  var documentStart = state.position, _position, directiveName, directiveArgs, hasDirectives = false, ch;
  state.version = null;
  state.checkLineBreaks = state.legacy;
  state.tagMap = /* @__PURE__ */ Object.create(null);
  state.anchorMap = /* @__PURE__ */ Object.create(null);
  while ((ch = state.input.charCodeAt(state.position)) !== 0) {
    skipSeparationSpace(state, true, -1);
    ch = state.input.charCodeAt(state.position);
    if (state.lineIndent > 0 || ch !== 37) {
      break;
    }
    hasDirectives = true;
    ch = state.input.charCodeAt(++state.position);
    _position = state.position;
    while (ch !== 0 && !is_WS_OR_EOL(ch)) {
      ch = state.input.charCodeAt(++state.position);
    }
    directiveName = state.input.slice(_position, state.position);
    directiveArgs = [];
    if (directiveName.length < 1) {
      throwError(state, "directive name must not be less than one character in length");
    }
    while (ch !== 0) {
      while (is_WHITE_SPACE(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }
      if (ch === 35) {
        do {
          ch = state.input.charCodeAt(++state.position);
        } while (ch !== 0 && !is_EOL(ch));
        break;
      }
      if (is_EOL(ch)) break;
      _position = state.position;
      while (ch !== 0 && !is_WS_OR_EOL(ch)) {
        ch = state.input.charCodeAt(++state.position);
      }
      directiveArgs.push(state.input.slice(_position, state.position));
    }
    if (ch !== 0) readLineBreak(state);
    if (_hasOwnProperty$1.call(directiveHandlers, directiveName)) {
      directiveHandlers[directiveName](state, directiveName, directiveArgs);
    } else {
      throwWarning(state, 'unknown document directive "' + directiveName + '"');
    }
  }
  skipSeparationSpace(state, true, -1);
  if (state.lineIndent === 0 && state.input.charCodeAt(state.position) === 45 && state.input.charCodeAt(state.position + 1) === 45 && state.input.charCodeAt(state.position + 2) === 45) {
    state.position += 3;
    skipSeparationSpace(state, true, -1);
  } else if (hasDirectives) {
    throwError(state, "directives end mark is expected");
  }
  composeNode(state, state.lineIndent - 1, CONTEXT_BLOCK_OUT, false, true);
  skipSeparationSpace(state, true, -1);
  if (state.checkLineBreaks && PATTERN_NON_ASCII_LINE_BREAKS.test(state.input.slice(documentStart, state.position))) {
    throwWarning(state, "non-ASCII line breaks are interpreted as content");
  }
  state.documents.push(state.result);
  if (state.position === state.lineStart && testDocumentSeparator(state)) {
    if (state.input.charCodeAt(state.position) === 46) {
      state.position += 3;
      skipSeparationSpace(state, true, -1);
    }
    return;
  }
  if (state.position < state.length - 1) {
    throwError(state, "end of the stream or a document separator is expected");
  } else {
    return;
  }
}
function loadDocuments(input, options) {
  input = String(input);
  options = options || {};
  if (input.length !== 0) {
    if (input.charCodeAt(input.length - 1) !== 10 && input.charCodeAt(input.length - 1) !== 13) {
      input += "\n";
    }
    if (input.charCodeAt(0) === 65279) {
      input = input.slice(1);
    }
  }
  var state = new State$1(input, options);
  var nullpos = input.indexOf("\0");
  if (nullpos !== -1) {
    state.position = nullpos;
    throwError(state, "null byte is not allowed in input");
  }
  state.input += "\0";
  while (state.input.charCodeAt(state.position) === 32) {
    state.lineIndent += 1;
    state.position += 1;
  }
  while (state.position < state.length - 1) {
    readDocument(state);
  }
  return state.documents;
}
function loadAll$1(input, iterator, options) {
  if (iterator !== null && typeof iterator === "object" && typeof options === "undefined") {
    options = iterator;
    iterator = null;
  }
  var documents = loadDocuments(input, options);
  if (typeof iterator !== "function") {
    return documents;
  }
  for (var index = 0, length = documents.length; index < length; index += 1) {
    iterator(documents[index]);
  }
}
function load$1(input, options) {
  var documents = loadDocuments(input, options);
  if (documents.length === 0) {
    return void 0;
  } else if (documents.length === 1) {
    return documents[0];
  }
  throw new exception("expected a single document in the stream, but found more");
}
var loadAll_1 = loadAll$1;
var load_1 = load$1;
var loader = {
  loadAll: loadAll_1,
  load: load_1
};
var _toString = Object.prototype.toString;
var _hasOwnProperty = Object.prototype.hasOwnProperty;
var CHAR_BOM = 65279;
var CHAR_TAB = 9;
var CHAR_LINE_FEED = 10;
var CHAR_CARRIAGE_RETURN = 13;
var CHAR_SPACE = 32;
var CHAR_EXCLAMATION = 33;
var CHAR_DOUBLE_QUOTE = 34;
var CHAR_SHARP = 35;
var CHAR_PERCENT = 37;
var CHAR_AMPERSAND = 38;
var CHAR_SINGLE_QUOTE = 39;
var CHAR_ASTERISK = 42;
var CHAR_COMMA = 44;
var CHAR_MINUS = 45;
var CHAR_COLON = 58;
var CHAR_EQUALS = 61;
var CHAR_GREATER_THAN = 62;
var CHAR_QUESTION = 63;
var CHAR_COMMERCIAL_AT = 64;
var CHAR_LEFT_SQUARE_BRACKET = 91;
var CHAR_RIGHT_SQUARE_BRACKET = 93;
var CHAR_GRAVE_ACCENT = 96;
var CHAR_LEFT_CURLY_BRACKET = 123;
var CHAR_VERTICAL_LINE = 124;
var CHAR_RIGHT_CURLY_BRACKET = 125;
var ESCAPE_SEQUENCES = {};
ESCAPE_SEQUENCES[0] = "\\0";
ESCAPE_SEQUENCES[7] = "\\a";
ESCAPE_SEQUENCES[8] = "\\b";
ESCAPE_SEQUENCES[9] = "\\t";
ESCAPE_SEQUENCES[10] = "\\n";
ESCAPE_SEQUENCES[11] = "\\v";
ESCAPE_SEQUENCES[12] = "\\f";
ESCAPE_SEQUENCES[13] = "\\r";
ESCAPE_SEQUENCES[27] = "\\e";
ESCAPE_SEQUENCES[34] = '\\"';
ESCAPE_SEQUENCES[92] = "\\\\";
ESCAPE_SEQUENCES[133] = "\\N";
ESCAPE_SEQUENCES[160] = "\\_";
ESCAPE_SEQUENCES[8232] = "\\L";
ESCAPE_SEQUENCES[8233] = "\\P";
var DEPRECATED_BOOLEANS_SYNTAX = [
  "y",
  "Y",
  "yes",
  "Yes",
  "YES",
  "on",
  "On",
  "ON",
  "n",
  "N",
  "no",
  "No",
  "NO",
  "off",
  "Off",
  "OFF"
];
var DEPRECATED_BASE60_SYNTAX = /^[-+]?[0-9_]+(?::[0-9_]+)+(?:\.[0-9_]*)?$/;
function compileStyleMap(schema2, map2) {
  var result, keys, index, length, tag, style, type2;
  if (map2 === null) return {};
  result = {};
  keys = Object.keys(map2);
  for (index = 0, length = keys.length; index < length; index += 1) {
    tag = keys[index];
    style = String(map2[tag]);
    if (tag.slice(0, 2) === "!!") {
      tag = "tag:yaml.org,2002:" + tag.slice(2);
    }
    type2 = schema2.compiledTypeMap["fallback"][tag];
    if (type2 && _hasOwnProperty.call(type2.styleAliases, style)) {
      style = type2.styleAliases[style];
    }
    result[tag] = style;
  }
  return result;
}
function encodeHex(character) {
  var string, handle, length;
  string = character.toString(16).toUpperCase();
  if (character <= 255) {
    handle = "x";
    length = 2;
  } else if (character <= 65535) {
    handle = "u";
    length = 4;
  } else if (character <= 4294967295) {
    handle = "U";
    length = 8;
  } else {
    throw new exception("code point within a string may not be greater than 0xFFFFFFFF");
  }
  return "\\" + handle + common.repeat("0", length - string.length) + string;
}
var QUOTING_TYPE_SINGLE = 1;
var QUOTING_TYPE_DOUBLE = 2;
function State(options) {
  this.schema = options["schema"] || _default;
  this.indent = Math.max(1, options["indent"] || 2);
  this.noArrayIndent = options["noArrayIndent"] || false;
  this.skipInvalid = options["skipInvalid"] || false;
  this.flowLevel = common.isNothing(options["flowLevel"]) ? -1 : options["flowLevel"];
  this.styleMap = compileStyleMap(this.schema, options["styles"] || null);
  this.sortKeys = options["sortKeys"] || false;
  this.lineWidth = options["lineWidth"] || 80;
  this.noRefs = options["noRefs"] || false;
  this.noCompatMode = options["noCompatMode"] || false;
  this.condenseFlow = options["condenseFlow"] || false;
  this.quotingType = options["quotingType"] === '"' ? QUOTING_TYPE_DOUBLE : QUOTING_TYPE_SINGLE;
  this.forceQuotes = options["forceQuotes"] || false;
  this.replacer = typeof options["replacer"] === "function" ? options["replacer"] : null;
  this.implicitTypes = this.schema.compiledImplicit;
  this.explicitTypes = this.schema.compiledExplicit;
  this.tag = null;
  this.result = "";
  this.duplicates = [];
  this.usedDuplicates = null;
}
function indentString(string, spaces) {
  var ind = common.repeat(" ", spaces), position = 0, next = -1, result = "", line, length = string.length;
  while (position < length) {
    next = string.indexOf("\n", position);
    if (next === -1) {
      line = string.slice(position);
      position = length;
    } else {
      line = string.slice(position, next + 1);
      position = next + 1;
    }
    if (line.length && line !== "\n") result += ind;
    result += line;
  }
  return result;
}
function generateNextLine(state, level) {
  return "\n" + common.repeat(" ", state.indent * level);
}
function testImplicitResolving(state, str2) {
  var index, length, type2;
  for (index = 0, length = state.implicitTypes.length; index < length; index += 1) {
    type2 = state.implicitTypes[index];
    if (type2.resolve(str2)) {
      return true;
    }
  }
  return false;
}
function isWhitespace(c) {
  return c === CHAR_SPACE || c === CHAR_TAB;
}
function isPrintable(c) {
  return 32 <= c && c <= 126 || 161 <= c && c <= 55295 && c !== 8232 && c !== 8233 || 57344 <= c && c <= 65533 && c !== CHAR_BOM || 65536 <= c && c <= 1114111;
}
function isNsCharOrWhitespace(c) {
  return isPrintable(c) && c !== CHAR_BOM && c !== CHAR_CARRIAGE_RETURN && c !== CHAR_LINE_FEED;
}
function isPlainSafe(c, prev, inblock) {
  var cIsNsCharOrWhitespace = isNsCharOrWhitespace(c);
  var cIsNsChar = cIsNsCharOrWhitespace && !isWhitespace(c);
  return (
    // ns-plain-safe
    (inblock ? (
      // c = flow-in
      cIsNsCharOrWhitespace
    ) : cIsNsCharOrWhitespace && c !== CHAR_COMMA && c !== CHAR_LEFT_SQUARE_BRACKET && c !== CHAR_RIGHT_SQUARE_BRACKET && c !== CHAR_LEFT_CURLY_BRACKET && c !== CHAR_RIGHT_CURLY_BRACKET) && c !== CHAR_SHARP && !(prev === CHAR_COLON && !cIsNsChar) || isNsCharOrWhitespace(prev) && !isWhitespace(prev) && c === CHAR_SHARP || prev === CHAR_COLON && cIsNsChar
  );
}
function isPlainSafeFirst(c) {
  return isPrintable(c) && c !== CHAR_BOM && !isWhitespace(c) && c !== CHAR_MINUS && c !== CHAR_QUESTION && c !== CHAR_COLON && c !== CHAR_COMMA && c !== CHAR_LEFT_SQUARE_BRACKET && c !== CHAR_RIGHT_SQUARE_BRACKET && c !== CHAR_LEFT_CURLY_BRACKET && c !== CHAR_RIGHT_CURLY_BRACKET && c !== CHAR_SHARP && c !== CHAR_AMPERSAND && c !== CHAR_ASTERISK && c !== CHAR_EXCLAMATION && c !== CHAR_VERTICAL_LINE && c !== CHAR_EQUALS && c !== CHAR_GREATER_THAN && c !== CHAR_SINGLE_QUOTE && c !== CHAR_DOUBLE_QUOTE && c !== CHAR_PERCENT && c !== CHAR_COMMERCIAL_AT && c !== CHAR_GRAVE_ACCENT;
}
function isPlainSafeLast(c) {
  return !isWhitespace(c) && c !== CHAR_COLON;
}
function codePointAt(string, pos) {
  var first = string.charCodeAt(pos), second;
  if (first >= 55296 && first <= 56319 && pos + 1 < string.length) {
    second = string.charCodeAt(pos + 1);
    if (second >= 56320 && second <= 57343) {
      return (first - 55296) * 1024 + second - 56320 + 65536;
    }
  }
  return first;
}
function needIndentIndicator(string) {
  var leadingSpaceRe = /^\n* /;
  return leadingSpaceRe.test(string);
}
var STYLE_PLAIN = 1;
var STYLE_SINGLE = 2;
var STYLE_LITERAL = 3;
var STYLE_FOLDED = 4;
var STYLE_DOUBLE = 5;
function chooseScalarStyle(string, singleLineOnly, indentPerLevel, lineWidth, testAmbiguousType, quotingType, forceQuotes, inblock) {
  var i2;
  var char = 0;
  var prevChar = null;
  var hasLineBreak = false;
  var hasFoldableLine = false;
  var shouldTrackWidth = lineWidth !== -1;
  var previousLineBreak = -1;
  var plain = isPlainSafeFirst(codePointAt(string, 0)) && isPlainSafeLast(codePointAt(string, string.length - 1));
  if (singleLineOnly || forceQuotes) {
    for (i2 = 0; i2 < string.length; char >= 65536 ? i2 += 2 : i2++) {
      char = codePointAt(string, i2);
      if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
  } else {
    for (i2 = 0; i2 < string.length; char >= 65536 ? i2 += 2 : i2++) {
      char = codePointAt(string, i2);
      if (char === CHAR_LINE_FEED) {
        hasLineBreak = true;
        if (shouldTrackWidth) {
          hasFoldableLine = hasFoldableLine || // Foldable line = too long, and not more-indented.
          i2 - previousLineBreak - 1 > lineWidth && string[previousLineBreak + 1] !== " ";
          previousLineBreak = i2;
        }
      } else if (!isPrintable(char)) {
        return STYLE_DOUBLE;
      }
      plain = plain && isPlainSafe(char, prevChar, inblock);
      prevChar = char;
    }
    hasFoldableLine = hasFoldableLine || shouldTrackWidth && (i2 - previousLineBreak - 1 > lineWidth && string[previousLineBreak + 1] !== " ");
  }
  if (!hasLineBreak && !hasFoldableLine) {
    if (plain && !forceQuotes && !testAmbiguousType(string)) {
      return STYLE_PLAIN;
    }
    return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
  }
  if (indentPerLevel > 9 && needIndentIndicator(string)) {
    return STYLE_DOUBLE;
  }
  if (!forceQuotes) {
    return hasFoldableLine ? STYLE_FOLDED : STYLE_LITERAL;
  }
  return quotingType === QUOTING_TYPE_DOUBLE ? STYLE_DOUBLE : STYLE_SINGLE;
}
function writeScalar(state, string, level, iskey, inblock) {
  state.dump = (function() {
    if (string.length === 0) {
      return state.quotingType === QUOTING_TYPE_DOUBLE ? '""' : "''";
    }
    if (!state.noCompatMode) {
      if (DEPRECATED_BOOLEANS_SYNTAX.indexOf(string) !== -1 || DEPRECATED_BASE60_SYNTAX.test(string)) {
        return state.quotingType === QUOTING_TYPE_DOUBLE ? '"' + string + '"' : "'" + string + "'";
      }
    }
    var indent = state.indent * Math.max(1, level);
    var lineWidth = state.lineWidth === -1 ? -1 : Math.max(Math.min(state.lineWidth, 40), state.lineWidth - indent);
    var singleLineOnly = iskey || state.flowLevel > -1 && level >= state.flowLevel;
    function testAmbiguity(string2) {
      return testImplicitResolving(state, string2);
    }
    switch (chooseScalarStyle(
      string,
      singleLineOnly,
      state.indent,
      lineWidth,
      testAmbiguity,
      state.quotingType,
      state.forceQuotes && !iskey,
      inblock
    )) {
      case STYLE_PLAIN:
        return string;
      case STYLE_SINGLE:
        return "'" + string.replace(/'/g, "''") + "'";
      case STYLE_LITERAL:
        return "|" + blockHeader(string, state.indent) + dropEndingNewline(indentString(string, indent));
      case STYLE_FOLDED:
        return ">" + blockHeader(string, state.indent) + dropEndingNewline(indentString(foldString(string, lineWidth), indent));
      case STYLE_DOUBLE:
        return '"' + escapeString(string) + '"';
      default:
        throw new exception("impossible error: invalid scalar style");
    }
  })();
}
function blockHeader(string, indentPerLevel) {
  var indentIndicator = needIndentIndicator(string) ? String(indentPerLevel) : "";
  var clip = string[string.length - 1] === "\n";
  var keep = clip && (string[string.length - 2] === "\n" || string === "\n");
  var chomp = keep ? "+" : clip ? "" : "-";
  return indentIndicator + chomp + "\n";
}
function dropEndingNewline(string) {
  return string[string.length - 1] === "\n" ? string.slice(0, -1) : string;
}
function foldString(string, width) {
  var lineRe = /(\n+)([^\n]*)/g;
  var result = (function() {
    var nextLF = string.indexOf("\n");
    nextLF = nextLF !== -1 ? nextLF : string.length;
    lineRe.lastIndex = nextLF;
    return foldLine(string.slice(0, nextLF), width);
  })();
  var prevMoreIndented = string[0] === "\n" || string[0] === " ";
  var moreIndented;
  var match;
  while (match = lineRe.exec(string)) {
    var prefix = match[1], line = match[2];
    moreIndented = line[0] === " ";
    result += prefix + (!prevMoreIndented && !moreIndented && line !== "" ? "\n" : "") + foldLine(line, width);
    prevMoreIndented = moreIndented;
  }
  return result;
}
function foldLine(line, width) {
  if (line === "" || line[0] === " ") return line;
  var breakRe = / [^ ]/g;
  var match;
  var start = 0, end, curr = 0, next = 0;
  var result = "";
  while (match = breakRe.exec(line)) {
    next = match.index;
    if (next - start > width) {
      end = curr > start ? curr : next;
      result += "\n" + line.slice(start, end);
      start = end + 1;
    }
    curr = next;
  }
  result += "\n";
  if (line.length - start > width && curr > start) {
    result += line.slice(start, curr) + "\n" + line.slice(curr + 1);
  } else {
    result += line.slice(start);
  }
  return result.slice(1);
}
function escapeString(string) {
  var result = "";
  var char = 0;
  var escapeSeq;
  for (var i2 = 0; i2 < string.length; char >= 65536 ? i2 += 2 : i2++) {
    char = codePointAt(string, i2);
    escapeSeq = ESCAPE_SEQUENCES[char];
    if (!escapeSeq && isPrintable(char)) {
      result += string[i2];
      if (char >= 65536) result += string[i2 + 1];
    } else {
      result += escapeSeq || encodeHex(char);
    }
  }
  return result;
}
function writeFlowSequence(state, level, object) {
  var _result = "", _tag = state.tag, index, length, value;
  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];
    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }
    if (writeNode(state, level, value, false, false) || typeof value === "undefined" && writeNode(state, level, null, false, false)) {
      if (_result !== "") _result += "," + (!state.condenseFlow ? " " : "");
      _result += state.dump;
    }
  }
  state.tag = _tag;
  state.dump = "[" + _result + "]";
}
function writeBlockSequence(state, level, object, compact) {
  var _result = "", _tag = state.tag, index, length, value;
  for (index = 0, length = object.length; index < length; index += 1) {
    value = object[index];
    if (state.replacer) {
      value = state.replacer.call(object, String(index), value);
    }
    if (writeNode(state, level + 1, value, true, true, false, true) || typeof value === "undefined" && writeNode(state, level + 1, null, true, true, false, true)) {
      if (!compact || _result !== "") {
        _result += generateNextLine(state, level);
      }
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        _result += "-";
      } else {
        _result += "- ";
      }
      _result += state.dump;
    }
  }
  state.tag = _tag;
  state.dump = _result || "[]";
}
function writeFlowMapping(state, level, object) {
  var _result = "", _tag = state.tag, objectKeyList = Object.keys(object), index, length, objectKey, objectValue, pairBuffer;
  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = "";
    if (_result !== "") pairBuffer += ", ";
    if (state.condenseFlow) pairBuffer += '"';
    objectKey = objectKeyList[index];
    objectValue = object[objectKey];
    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }
    if (!writeNode(state, level, objectKey, false, false)) {
      continue;
    }
    if (state.dump.length > 1024) pairBuffer += "? ";
    pairBuffer += state.dump + (state.condenseFlow ? '"' : "") + ":" + (state.condenseFlow ? "" : " ");
    if (!writeNode(state, level, objectValue, false, false)) {
      continue;
    }
    pairBuffer += state.dump;
    _result += pairBuffer;
  }
  state.tag = _tag;
  state.dump = "{" + _result + "}";
}
function writeBlockMapping(state, level, object, compact) {
  var _result = "", _tag = state.tag, objectKeyList = Object.keys(object), index, length, objectKey, objectValue, explicitPair, pairBuffer;
  if (state.sortKeys === true) {
    objectKeyList.sort();
  } else if (typeof state.sortKeys === "function") {
    objectKeyList.sort(state.sortKeys);
  } else if (state.sortKeys) {
    throw new exception("sortKeys must be a boolean or a function");
  }
  for (index = 0, length = objectKeyList.length; index < length; index += 1) {
    pairBuffer = "";
    if (!compact || _result !== "") {
      pairBuffer += generateNextLine(state, level);
    }
    objectKey = objectKeyList[index];
    objectValue = object[objectKey];
    if (state.replacer) {
      objectValue = state.replacer.call(object, objectKey, objectValue);
    }
    if (!writeNode(state, level + 1, objectKey, true, true, true)) {
      continue;
    }
    explicitPair = state.tag !== null && state.tag !== "?" || state.dump && state.dump.length > 1024;
    if (explicitPair) {
      if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
        pairBuffer += "?";
      } else {
        pairBuffer += "? ";
      }
    }
    pairBuffer += state.dump;
    if (explicitPair) {
      pairBuffer += generateNextLine(state, level);
    }
    if (!writeNode(state, level + 1, objectValue, true, explicitPair)) {
      continue;
    }
    if (state.dump && CHAR_LINE_FEED === state.dump.charCodeAt(0)) {
      pairBuffer += ":";
    } else {
      pairBuffer += ": ";
    }
    pairBuffer += state.dump;
    _result += pairBuffer;
  }
  state.tag = _tag;
  state.dump = _result || "{}";
}
function detectType(state, object, explicit) {
  var _result, typeList, index, length, type2, style;
  typeList = explicit ? state.explicitTypes : state.implicitTypes;
  for (index = 0, length = typeList.length; index < length; index += 1) {
    type2 = typeList[index];
    if ((type2.instanceOf || type2.predicate) && (!type2.instanceOf || typeof object === "object" && object instanceof type2.instanceOf) && (!type2.predicate || type2.predicate(object))) {
      if (explicit) {
        if (type2.multi && type2.representName) {
          state.tag = type2.representName(object);
        } else {
          state.tag = type2.tag;
        }
      } else {
        state.tag = "?";
      }
      if (type2.represent) {
        style = state.styleMap[type2.tag] || type2.defaultStyle;
        if (_toString.call(type2.represent) === "[object Function]") {
          _result = type2.represent(object, style);
        } else if (_hasOwnProperty.call(type2.represent, style)) {
          _result = type2.represent[style](object, style);
        } else {
          throw new exception("!<" + type2.tag + '> tag resolver accepts not "' + style + '" style');
        }
        state.dump = _result;
      }
      return true;
    }
  }
  return false;
}
function writeNode(state, level, object, block, compact, iskey, isblockseq) {
  state.tag = null;
  state.dump = object;
  if (!detectType(state, object, false)) {
    detectType(state, object, true);
  }
  var type2 = _toString.call(state.dump);
  var inblock = block;
  var tagStr;
  if (block) {
    block = state.flowLevel < 0 || state.flowLevel > level;
  }
  var objectOrArray = type2 === "[object Object]" || type2 === "[object Array]", duplicateIndex, duplicate;
  if (objectOrArray) {
    duplicateIndex = state.duplicates.indexOf(object);
    duplicate = duplicateIndex !== -1;
  }
  if (state.tag !== null && state.tag !== "?" || duplicate || state.indent !== 2 && level > 0) {
    compact = false;
  }
  if (duplicate && state.usedDuplicates[duplicateIndex]) {
    state.dump = "*ref_" + duplicateIndex;
  } else {
    if (objectOrArray && duplicate && !state.usedDuplicates[duplicateIndex]) {
      state.usedDuplicates[duplicateIndex] = true;
    }
    if (type2 === "[object Object]") {
      if (block && Object.keys(state.dump).length !== 0) {
        writeBlockMapping(state, level, state.dump, compact);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + state.dump;
        }
      } else {
        writeFlowMapping(state, level, state.dump);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + " " + state.dump;
        }
      }
    } else if (type2 === "[object Array]") {
      if (block && state.dump.length !== 0) {
        if (state.noArrayIndent && !isblockseq && level > 0) {
          writeBlockSequence(state, level - 1, state.dump, compact);
        } else {
          writeBlockSequence(state, level, state.dump, compact);
        }
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + state.dump;
        }
      } else {
        writeFlowSequence(state, level, state.dump);
        if (duplicate) {
          state.dump = "&ref_" + duplicateIndex + " " + state.dump;
        }
      }
    } else if (type2 === "[object String]") {
      if (state.tag !== "?") {
        writeScalar(state, state.dump, level, iskey, inblock);
      }
    } else if (type2 === "[object Undefined]") {
      return false;
    } else {
      if (state.skipInvalid) return false;
      throw new exception("unacceptable kind of an object to dump " + type2);
    }
    if (state.tag !== null && state.tag !== "?") {
      tagStr = encodeURI(
        state.tag[0] === "!" ? state.tag.slice(1) : state.tag
      ).replace(/!/g, "%21");
      if (state.tag[0] === "!") {
        tagStr = "!" + tagStr;
      } else if (tagStr.slice(0, 18) === "tag:yaml.org,2002:") {
        tagStr = "!!" + tagStr.slice(18);
      } else {
        tagStr = "!<" + tagStr + ">";
      }
      state.dump = tagStr + " " + state.dump;
    }
  }
  return true;
}
function getDuplicateReferences(object, state) {
  var objects = [], duplicatesIndexes = [], index, length;
  inspectNode(object, objects, duplicatesIndexes);
  for (index = 0, length = duplicatesIndexes.length; index < length; index += 1) {
    state.duplicates.push(objects[duplicatesIndexes[index]]);
  }
  state.usedDuplicates = new Array(length);
}
function inspectNode(object, objects, duplicatesIndexes) {
  var objectKeyList, index, length;
  if (object !== null && typeof object === "object") {
    index = objects.indexOf(object);
    if (index !== -1) {
      if (duplicatesIndexes.indexOf(index) === -1) {
        duplicatesIndexes.push(index);
      }
    } else {
      objects.push(object);
      if (Array.isArray(object)) {
        for (index = 0, length = object.length; index < length; index += 1) {
          inspectNode(object[index], objects, duplicatesIndexes);
        }
      } else {
        objectKeyList = Object.keys(object);
        for (index = 0, length = objectKeyList.length; index < length; index += 1) {
          inspectNode(object[objectKeyList[index]], objects, duplicatesIndexes);
        }
      }
    }
  }
}
function dump$1(input, options) {
  options = options || {};
  var state = new State(options);
  if (!state.noRefs) getDuplicateReferences(input, state);
  var value = input;
  if (state.replacer) {
    value = state.replacer.call({ "": value }, "", value);
  }
  if (writeNode(state, 0, value, true, true)) return state.dump + "\n";
  return "";
}
var dump_1 = dump$1;
var dumper = {
  dump: dump_1
};
function renamed(from, to) {
  return function() {
    throw new Error("Function yaml." + from + " is removed in js-yaml 4. Use yaml." + to + " instead, which is now safe by default.");
  };
}
var load = loader.load;
var loadAll = loader.loadAll;
var dump = dumper.dump;
var safeLoad = renamed("safeLoad", "load");
var safeLoadAll = renamed("safeLoadAll", "loadAll");
var safeDump = renamed("safeDump", "dump");

// ../_research/lcm-full-20261021/src/prompts/loader.ts
var __dirname = dirname2(fileURLToPath2(import.meta.url));
var PROMPTS_DIR = existsSync(join2(__dirname, "assets", "prompts")) ? join2(__dirname, "assets", "prompts") : __dirname;

// ../_research/lcm-full-20261021/src/store/language-pack.ts
var RESCAN_INTERVAL_MS = 3e4;
var BUILTIN_PACKS = /* @__PURE__ */ new Map([
  ["en", /* @__PURE__ */ new Set([
    "a",
    "an",
    "the",
    "and",
    "or",
    "but",
    "if",
    "then",
    "else",
    "when",
    "while",
    "at",
    "by",
    "for",
    "with",
    "about",
    "into",
    "through",
    "during",
    "before",
    "after",
    "above",
    "below",
    "between",
    "to",
    "from",
    "up",
    "down",
    "in",
    "out",
    "on",
    "off",
    "over",
    "under",
    "again",
    "further",
    "once",
    "of",
    "here",
    "there",
    "all",
    "any",
    "both",
    "each",
    "few",
    "more",
    "most",
    "other",
    "some",
    "such",
    "no",
    "nor",
    "not",
    "only",
    "own",
    "same",
    "so",
    "than",
    "too",
    "very",
    "just",
    "as",
    "is",
    "am",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "have",
    "has",
    "had",
    "having",
    "do",
    "does",
    "did",
    "doing",
    "would",
    "should",
    "could",
    "ought",
    "i",
    "you",
    "he",
    "she",
    "it",
    "we",
    "they",
    "them",
    "his",
    "her",
    "their",
    "our",
    "your",
    "my",
    "its",
    "me",
    "him",
    "us",
    "this",
    "that",
    "these",
    "those",
    "what",
    "which",
    "who",
    "whom",
    "how",
    "why",
    "where",
    "can",
    "will",
    "shall",
    "may",
    "might",
    "must",
    "let",
    "make",
    "made",
    "get",
    "got",
    "go",
    "went",
    "say",
    "said",
    "tell",
    "told",
    "know",
    "knew",
    "think",
    "thought",
    "want",
    "wanted",
    "use",
    "used",
    "using",
    "way",
    "thing",
    "things",
    "something",
    "anything",
    "everything",
    "nothing",
    "someone",
    "anyone",
    "everyone",
    "somewhere",
    "anywhere",
    "everywhere",
    "s",
    "t",
    "d",
    "ll",
    "re",
    "ve"
  ])]
]);
function primarySubtag(tag) {
  return tag.trim().toLowerCase().split("-")[0];
}
function languagePacksDir(paths) {
  if (paths) return join3(paths.home, "languages");
  const override = process.env.LCM_LANGUAGES_DIR;
  if (!override) throw new Error("language packs require an LcmPaths storage root");
  return override;
}
var loaded = null;
var warned = /* @__PURE__ */ new Set();
function warnOnce(key, message) {
  if (warned.has(key)) return;
  warned.add(key);
  console.warn(`[lcm] ${message}`);
}
function readPack(path) {
  const parsed = JSON.parse(readFileSync2(path, "utf-8"));
  if (parsed.version !== 1 || typeof parsed.tag !== "string" || !Array.isArray(parsed.stopwords)) return null;
  const stopwords = parsed.stopwords.filter((w) => typeof w === "string");
  return { version: 1, tag: parsed.tag, stopwords, generatedBy: parsed.generatedBy, generatedAt: parsed.generatedAt ?? "" };
}
function loadLanguagePacks(paths) {
  const dir = languagePacksDir(paths);
  const now = Date.now();
  let dirMtimeMs = -1;
  try {
    dirMtimeMs = statSync(dir).mtimeMs;
  } catch {
  }
  if (loaded && loaded.dir === dir && loaded.dirMtimeMs === dirMtimeMs && now - loaded.scannedAt < RESCAN_INTERVAL_MS) {
    return loaded.packs;
  }
  const packs = /* @__PURE__ */ new Map();
  if (dirMtimeMs >= 0) {
    for (const name of readdirSync(dir)) {
      if (!name.endsWith(".json")) continue;
      const path = join3(dir, name);
      try {
        const pack = readPack(path);
        if (!pack) throw new Error("not a version 1 language pack");
        packs.set(pack.tag, new Set(pack.stopwords.map((w) => w.toLowerCase())));
      } catch (err) {
        warnOnce(path, `language pack ${path} skipped: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }
  loaded = { dir, scannedAt: now, dirMtimeMs, packs };
  return packs;
}
function packStopwordsFor(languages, paths) {
  if (languages.length === 0) return EMPTY;
  const wanted = new Set(languages.map(primarySubtag));
  let diskPacks = EMPTY_PACKS;
  try {
    diskPacks = loadLanguagePacks(paths);
  } catch {
  }
  const overridden = new Set([...diskPacks.keys()].map(primarySubtag));
  const chosen = /* @__PURE__ */ new Set();
  for (const [tag, stopwords] of diskPacks) {
    if (!wanted.has(primarySubtag(tag))) continue;
    for (const word of stopwords) chosen.add(word);
  }
  for (const [tag, stopwords] of BUILTIN_PACKS) {
    if (!wanted.has(tag) || overridden.has(tag)) continue;
    for (const word of stopwords) chosen.add(word);
  }
  return chosen;
}
var EMPTY = /* @__PURE__ */ new Set();
var EMPTY_PACKS = /* @__PURE__ */ new Map();

// ../_research/lcm-full-20261021/src/store/fts5-query.ts
var TERM_SPLIT_RE = /[^\p{L}\p{N}]+/u;
function quote(term) {
  return `"${term.replace(/"/g, "")}"`;
}
function dedupe(words) {
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const word of words) {
    if (!seen.has(word)) {
      seen.add(word);
      out.push(word);
    }
  }
  return out;
}
function extractQueryTerms(raw, paths, languages = []) {
  const words = dedupe(
    raw.toLowerCase().split(TERM_SPLIT_RE).filter(Boolean)
  );
  let packStopwords = /* @__PURE__ */ new Set();
  try {
    packStopwords = packStopwordsFor(languages, paths);
  } catch {
  }
  const terms = words.filter((word) => !packStopwords.has(word));
  if (terms.length > 0) {
    return terms;
  }
  return words;
}
var MAX_QUERY_TERMS = 32;
var MAX_TERM_LENGTH = 64;
function prepareFts5Query(raw, preExtracted, paths) {
  const terms = (preExtracted ? [...preExtracted] : extractQueryTerms(raw, paths)).filter((term) => term.length <= MAX_TERM_LENGTH).slice(0, MAX_QUERY_TERMS);
  if (terms.length === 0) {
    return null;
  }
  const quoted = terms.map(quote);
  return { terms, and: quoted.join(" "), or: quoted.join(" OR ") };
}
function shouldRetryWithLike(prepared) {
  return prepared.terms.length > 1;
}
function likePlanForPreparedQuery(column, prepared) {
  const plan = buildLikeSearchPlan(column, prepared.terms.join(" "));
  return { terms: plan.terms, where: plan.where, args: plan.args };
}
function byRankThenNewest(rows) {
  return rows.sort((a, b) => (a.rank ?? 0) - (b.rank ?? 0) || b.createdAt.getTime() - a.createdAt.getTime());
}

// ../_research/lcm-full-20261021/src/store/regex-safety.ts
var import_safe_regex = __toESM(require_safe_regex(), 1);
function validateRegex(pattern) {
  let re;
  try {
    re = new RegExp(pattern);
  } catch (err) {
    throw new Error(`Invalid regex pattern: ${err instanceof Error ? err.message : "syntax error"}`);
  }
  let safe;
  try {
    safe = (0, import_safe_regex.default)(pattern);
  } catch {
    safe = false;
  }
  if (!safe) {
    throw new Error(`Unsafe regex pattern rejected (potential catastrophic backtracking): ${pattern}`);
  }
  return re;
}

// ../_research/lcm-full-20261021/src/store/conversation-store.ts
var MESSAGE_SEARCH_CONTENT_SQL = `content || COALESCE((
  SELECT char(10) || group_concat(input, char(10)) FROM transcript_tool_calls
  WHERE message_id = messages.message_id
), '')`;
var memoryDatabaseIds = /* @__PURE__ */ new WeakMap();
var messageColumnsByConnection = /* @__PURE__ */ new WeakMap();
var CONVERSATION_SELECT_COLUMNS = `SELECT conversation_id, session_id, title, bootstrapped_at, created_at, updated_at,
       role_tagging, parser_shape, parent_session_id, subagent_type, subagent_desc`;
function toConversationRecord(row) {
  return {
    conversationId: row.conversation_id,
    sessionId: row.session_id,
    title: row.title,
    bootstrappedAt: row.bootstrapped_at ? parseSqliteDate(row.bootstrapped_at) : null,
    createdAt: parseSqliteDate(row.created_at),
    updatedAt: parseSqliteDate(row.updated_at),
    roleTagging: row.role_tagging === "tagged" ? "tagged" : null,
    parserShape: row.parser_shape,
    parentSessionId: row.parent_session_id,
    subagentType: row.subagent_type,
    subagentDesc: row.subagent_desc
  };
}
function toMessageRecord(row) {
  if (row.event_time_source != null && row.event_time_source !== "transcript" && row.event_time_source !== "commit") {
    throw new Error("Invalid event time source");
  }
  return {
    messageId: row.message_id,
    conversationId: row.conversation_id,
    seq: row.seq,
    eventAt: row.event_at ? parseSqliteDate(row.event_at) : null,
    eventTimeSource: row.event_time_source ?? (row.event_at ? "transcript" : null),
    role: row.role,
    content: row.content,
    tokenCount: row.token_count,
    createdAt: parseSqliteDate(row.created_at)
  };
}
function toSearchResult(row) {
  return {
    messageId: row.message_id,
    conversationId: row.conversation_id,
    role: row.role,
    snippet: row.snippet,
    createdAt: parseSqliteDate(row.created_at),
    rank: row.rank
  };
}
var NOT_COMPACTION_EVENT = `NOT EXISTS (
  SELECT 1 FROM message_parts p WHERE p.message_id = m.message_id AND p.part_type = 'compaction'
)`;
var ConversationStore = class {
  constructor(db, options) {
    this.db = db;
    this.fts5Available = options?.fts5Available ?? true;
  }
  db;
  fts5Available;
  messageByIdStatement;
  sessionFilter(alias = "") {
    const exists = this.db.prepare("PRAGMA table_info(conversations)").all().some((column) => column.name === "is_timeline");
    return exists ? `${alias}is_timeline = 0` : "1";
  }
  getSessionCommitReferences(sessionId) {
    return new CommitStore(this.db).forSession(sessionId);
  }
  getToolLessonsForMessages(messageIds) {
    return new ToolLessonStore(this.db).forMessages(messageIds);
  }
  /** Read-only callers may open a store before its next schema migration. */
  messageColumns() {
    let columns = messageColumnsByConnection.get(this.db);
    if (!columns) {
      const rows = this.db.prepare("PRAGMA table_info(messages)").all();
      columns = new Set(rows.map((column) => column.name));
      messageColumnsByConnection.set(this.db, columns);
    }
    return columns;
  }
  eventTimeColumn(alias = "") {
    return this.messageColumns().has("event_at") ? `${alias}event_at` : "NULL";
  }
  eventSourceColumn(alias = "") {
    return this.messageColumns().has("event_time_source") ? `${alias}event_time_source` : "NULL";
  }
  /** Source bounds are requested separately so ordinary conversation reads never scan messages. */
  async getConversationTimeBounds(conversationId) {
    const event = this.eventTimeColumn("m.");
    const row = this.db.prepare(`SELECT
      COALESCE(strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(MIN(julianday(${event})), MIN(julianday(m.created_at)))), c.created_at) first_at,
      COALESCE(strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(MAX(julianday(${event})), MAX(julianday(m.created_at)))), c.created_at) last_at
      FROM conversations c LEFT JOIN messages m ON m.conversation_id = c.conversation_id AND ${NOT_COMPACTION_EVENT}
      WHERE c.conversation_id = ? GROUP BY c.conversation_id`).get(conversationId);
    return row ? { firstAt: parseSqliteDate(row.first_at), lastAt: parseSqliteDate(row.last_at) } : null;
  }
  // ── Transaction helpers ──────────────────────────────────────────────────
  async withTransaction(operation) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = await operation();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  // ── Conversation operations ───────────────────────────────────────────────
  async createConversation(input) {
    if (input.sessionId === TIMELINE_SESSION_ID) throw new Error("Reserved project timeline session");
    const result = this.db.prepare(
      `INSERT INTO conversations (session_id, title, role_tagging, parser_shape, parent_session_id, subagent_type, subagent_desc, opened_by_entry_id)
         VALUES (?, ?, 'tagged', ?, ?, ?, ?, ?)`
    ).run(
      input.sessionId,
      input.title ?? null,
      input.parserShape ?? null,
      input.parentSessionId ?? null,
      input.subagentType ?? null,
      input.subagentDesc ?? null,
      input.openedByEntryId ?? null
    );
    const row = this.db.prepare(`${CONVERSATION_SELECT_COLUMNS} FROM conversations WHERE conversation_id = ?`).get(Number(result.lastInsertRowid));
    return toConversationRecord(row);
  }
  isWorkerExcluded(conversationId) {
    const conversation = this.getConversationSync(conversationId);
    return Boolean(conversation && new WorkerStore(this.db).excluded(conversation.sessionId));
  }
  async getConversation(conversationId) {
    return this.getConversationSync(conversationId);
  }
  getConversationSync(conversationId) {
    const row = this.db.prepare(`${CONVERSATION_SELECT_COLUMNS} FROM conversations WHERE conversation_id = ?`).get(conversationId);
    return row ? toConversationRecord(row) : null;
  }
  async getConversationBySessionId(sessionId) {
    const row = this.db.prepare(
      `${CONVERSATION_SELECT_COLUMNS}
       FROM conversations
       WHERE session_id = ? AND ${this.sessionFilter()}
       ORDER BY created_at DESC, conversation_id DESC
       LIMIT 1`
    ).get(sessionId);
    return row ? toConversationRecord(row) : null;
  }
  async getOrCreateConversation(sessionId, title, attribution, parserShape) {
    const existing = await this.getConversationBySessionId(sessionId);
    if (existing) {
      return this.backfillAttribution(existing, attribution);
    }
    return this.createConversation({ sessionId, title, parserShape, ...attribution });
  }
  /**
   * The session's conversation opened by a clear at transcript entry `entryId`, creating it
   * when no conversation carries that entry yet. A session has one conversation per clear
   * after its first; the newest is the one {@link getConversationBySessionId} returns.
   */
  async getOrOpenConversationAt(sessionId, entryId, attribution, parserShape) {
    const row = this.db.prepare(`${CONVERSATION_SELECT_COLUMNS} FROM conversations WHERE session_id = ? AND opened_by_entry_id = ?`).get(sessionId, entryId);
    return row ? toConversationRecord(row) : this.createConversation({ sessionId, openedByEntryId: entryId, parserShape, ...attribution });
  }
  /** A Claude count can be reused only if every conversation used today's parser. */
  async sessionHasParserShape(sessionId, parserShape) {
    const row = this.db.prepare(
      "SELECT COUNT(*) AS n FROM conversations WHERE session_id = ? AND (parser_shape IS NULL OR parser_shape <> ?)"
    ).get(sessionId, parserShape);
    return row.n === 0;
  }
  /** Restamp a freshly rebuilt Claude conversation in the rebuild transaction. */
  setParserShape(conversationId, parserShape) {
    this.db.prepare("UPDATE conversations SET parser_shape = ? WHERE conversation_id = ? AND parser_shape IS NOT ?").run(parserShape, conversationId, parserShape);
  }
  /** Stamp every conversation after capture verified the session's stored prefix. */
  setSessionParserShape(sessionId, parserShape) {
    this.db.prepare("UPDATE conversations SET parser_shape = ? WHERE session_id = ? AND parser_shape IS NOT ?").run(parserShape, sessionId, parserShape);
  }
  /** Transcript messages stored across every conversation of the session; compaction's own event rows are not counted. */
  async getSessionMessageCount(sessionId) {
    const row = this.db.prepare(
      `SELECT COUNT(*) AS count FROM messages m
         JOIN conversations c ON c.conversation_id = m.conversation_id
         WHERE c.session_id = ? AND ${NOT_COMPACTION_EVENT}`
    ).get(sessionId);
    return row?.count ?? 0;
  }
  /** Every conversation's transcript messages of the session, oldest conversation first, each in `seq` order; compaction's own event rows are left out. */
  async getSessionMessages(sessionId, offset = 0, limit = -1) {
    const rows = this.db.prepare(
      `SELECT m.message_id, m.conversation_id, m.seq, m.role, m.content, m.token_count, m.created_at, ${this.eventTimeColumn("m.")} AS event_at, ${this.eventSourceColumn("m.")} AS event_time_source
         FROM messages m
         JOIN conversations c ON c.conversation_id = m.conversation_id
         WHERE c.session_id = ? AND ${NOT_COMPACTION_EVENT}
         ORDER BY c.created_at, c.conversation_id, m.seq LIMIT ? OFFSET ?`
    ).all(sessionId, limit, offset);
    return rows.map(toMessageRecord);
  }
  isTimelineSession(sessionId) {
    return Boolean(this.db.prepare("SELECT 1 FROM conversations WHERE session_id = ? AND is_timeline = 1 LIMIT 1").get(sessionId));
  }
  /** Keyset pages retain session order across clears without sorting or rereading message prefixes. */
  async *sessionMessagePages(sessionId, limit) {
    const conversations = this.db.prepare(`SELECT conversation_id FROM conversations WHERE session_id = ?
      ORDER BY created_at, conversation_id`).all(sessionId);
    const page = this.db.prepare(`SELECT m.message_id, m.conversation_id, m.seq, m.role, m.content, m.token_count,
      m.created_at, ${this.eventTimeColumn("m.")} AS event_at, ${this.eventSourceColumn("m.")} AS event_time_source FROM messages m
      WHERE m.conversation_id = ? AND m.seq > ? AND ${NOT_COMPACTION_EVENT} ORDER BY m.seq LIMIT ?`);
    for (const conversation of conversations) {
      let seq2 = -1;
      for (; ; ) {
        const rows = page.all(conversation.conversation_id, seq2, limit);
        if (rows.length) yield rows.map(toMessageRecord);
        if (rows.length < limit) break;
        seq2 = rows.at(-1).seq;
      }
    }
  }
  /** Fill unknown event times without changing capture timestamps or an earlier repair. */
  backfillMessageEventTimes(rows) {
    const update = this.db.prepare("UPDATE messages SET event_at = ?, event_time_source = 'transcript' WHERE message_id = ? AND (event_at IS NULL OR event_time_source = 'commit') AND content = ? AND role = ?");
    let updated = 0;
    for (const row of rows) updated += Number(update.run(row.eventAt, row.messageId, row.content, row.role).changes);
    return updated;
  }
  /** Rewrite only verified historical NUL-cut rows and their full-text entries as one unit. */
  repairCutMessageContent(rows) {
    if (rows.length === 0) return 0;
    const update = this.db.prepare(
      `UPDATE messages SET content = ?, event_time_source = CASE WHEN event_at IS NULL AND ? IS NOT NULL THEN 'transcript' ELSE event_time_source END, event_at = COALESCE(event_at, ?) WHERE message_id = ? AND
       (content = ? OR (instr(content, char(0)) > 0 AND substr(content, 1, instr(content, char(0)) - 1) = ?))`
    );
    const timelineTracking = this.db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'timeline_state'").get() && Boolean(this.db.prepare("SELECT tracking FROM timeline_state WHERE id = 1").get()?.tracking);
    const markDirty = timelineTracking ? this.db.prepare(`INSERT INTO timeline_dirty(session_id, rev)
      SELECT c.session_id, 1 FROM messages m JOIN conversations c ON c.conversation_id = m.conversation_id WHERE m.message_id = ?
      ON CONFLICT(session_id) DO UPDATE SET rev = rev + 1, dirty = 1, bumped_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`) : void 0;
    const hasFts = this.db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages_fts'").get() !== void 0;
    const removeFts = hasFts ? this.db.prepare("DELETE FROM messages_fts WHERE rowid = ?") : void 0;
    const addFts = hasFts ? this.db.prepare(`INSERT INTO messages_fts(rowid, content) SELECT ?, ? || COALESCE((
      SELECT char(10) || group_concat(input, char(10)) FROM transcript_tool_calls WHERE message_id = ?
    ), '')`) : void 0;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const row of rows) {
        if (update.run(row.content, row.eventAt ?? null, row.eventAt ?? null, row.messageId, row.storedContent, row.storedContent).changes !== 1) {
          throw new Error(`cut message ${row.messageId} changed before repair`);
        }
        markDirty?.run(row.messageId);
        removeFts?.run(row.messageId);
        addFts?.run(row.messageId, row.content, row.messageId);
      }
      this.db.exec("COMMIT");
      return rows.length;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  /** Cheap identity check for a validated prefix: stream raw rows, without hydration or redaction. */
  async getSessionPrefixFingerprint(sessionId, count) {
    const hash = createHash("sha256");
    const databases = this.db.prepare("PRAGMA database_list").all();
    const file = databases.find((entry) => entry.name === "main").file;
    if (file) {
      const stat = statSync2(file);
      hash.update(JSON.stringify([file, stat.dev, stat.ino]));
    } else {
      if (!memoryDatabaseIds.has(this.db)) memoryDatabaseIds.set(this.db, randomUUID());
      hash.update(memoryDatabaseIds.get(this.db));
    }
    for (const row of this.db.prepare(
      "SELECT conversation_id, created_at, role_tagging, parser_shape FROM conversations WHERE session_id = ? ORDER BY created_at, conversation_id"
    ).iterate(sessionId)) hash.update(JSON.stringify(row));
    for (const row of this.db.prepare(
      `SELECT m.message_id, m.conversation_id, m.seq, m.role, m.content
       FROM messages m JOIN conversations c ON c.conversation_id = m.conversation_id
       WHERE c.session_id = ? AND ${NOT_COMPACTION_EVENT}
       ORDER BY c.created_at, c.conversation_id, m.seq LIMIT ?`
    ).iterate(sessionId, count)) hash.update(JSON.stringify(row));
    return hash.digest("hex");
  }
  /**
   * Whether compaction has written its event rows into the session while every conversation of
   * it carries role tagging — the state in which stored history must be the current transcript's
   * prefix. A conversation from before role tagging cannot
   * be compared with a fresh parse of its transcript.
   */
  async sessionComparableAfterCompaction(sessionId) {
    const row = this.db.prepare(
      `SELECT
           EXISTS (SELECT 1 FROM messages m JOIN conversations c ON c.conversation_id = m.conversation_id
                   WHERE c.session_id = ? AND NOT ${NOT_COMPACTION_EVENT}) AS compacted,
           EXISTS (SELECT 1 FROM conversations WHERE session_id = ? AND role_tagging IS NULL) AS untagged`
    ).get(sessionId, sessionId);
    return row.compacted === 1 && row.untagged === 0;
  }
  /**
   * Fills a still-null attribution on an already-created row — the row was
   * captured before its `.meta.json` sidecar existed, or before whichever
   * caller passed attribution ran. Guarded by `parent_session_id IS NULL` so
   * a later read of an all-null sidecar can never clobber a row already
   * correctly attributed.
   */
  backfillAttribution(existing, attribution) {
    if (!attribution?.parentSessionId || existing.parentSessionId !== null) {
      return existing;
    }
    this.db.prepare(
      `UPDATE conversations
       SET parent_session_id = ?, subagent_type = ?, subagent_desc = ?
       WHERE conversation_id = ? AND parent_session_id IS NULL`
    ).run(attribution.parentSessionId, attribution.subagentType ?? null, attribution.subagentDesc ?? null, existing.conversationId);
    return this.getConversationSync(existing.conversationId) ?? existing;
  }
  async listConversations() {
    const rows = this.db.prepare(
      `${CONVERSATION_SELECT_COLUMNS}
       FROM conversations WHERE ${this.sessionFilter()}
       ORDER BY created_at`
    ).all();
    return rows.map(toConversationRecord);
  }
  /**
   * The conversation with the latest user/assistant message or summary,
   * leaving out the named session: what a session that has captured nothing
   * yet is shown in its place.
   */
  async latestActiveConversation(excludingSessionId) {
    const row = this.db.prepare(
      `${CONVERSATION_SELECT_COLUMNS.replaceAll("conversations.", "c.")}
       FROM conversations c
       WHERE c.session_id != ? AND ${this.sessionFilter("c.")}
         AND (EXISTS (
           SELECT 1 FROM messages m
           WHERE m.conversation_id = c.conversation_id AND m.role IN ('user', 'assistant')
         ) OR EXISTS (
           SELECT 1 FROM summaries s WHERE s.conversation_id = c.conversation_id
         ))
       ORDER BY MAX(
         COALESCE((
           SELECT MAX(julianday(m.created_at)) FROM messages m
           WHERE m.conversation_id = c.conversation_id
             AND m.role IN ('user', 'assistant')
         ), -1),
         COALESCE((
           SELECT MAX(julianday(s.created_at)) FROM summaries s
           WHERE s.conversation_id = c.conversation_id
         ), -1)
       ) DESC, c.conversation_id DESC
       LIMIT 1`
    ).get(excludingSessionId);
    return row ? toConversationRecord(row) : null;
  }
  // ── Message operations ────────────────────────────────────────────────────
  async createMessage(input) {
    const result = this.db.prepare(
      `INSERT INTO messages (conversation_id, seq, role, content, token_count, event_at, event_time_source)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(input.conversationId, input.seq, input.role, input.content, input.tokenCount, input.eventAt?.toISOString() ?? null, input.eventAt ? "transcript" : null);
    const messageId = Number(result.lastInsertRowid);
    this.indexMessageForFullText(messageId, input.content);
    const row = this.db.prepare(
      `SELECT message_id, conversation_id, seq, role, content, token_count, created_at, ${this.eventTimeColumn()} AS event_at, ${this.eventSourceColumn()} AS event_time_source
       FROM messages WHERE message_id = ?`
    ).get(messageId);
    return toMessageRecord(row);
  }
  async createMessagesBulk(inputs) {
    if (inputs.length === 0) {
      return [];
    }
    const insertStmt = this.db.prepare(
      `INSERT INTO messages (conversation_id, seq, role, content, token_count, event_at, event_time_source)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    const selectStmt = this.db.prepare(
      `SELECT message_id, conversation_id, seq, role, content, token_count, created_at, ${this.eventTimeColumn()} AS event_at, ${this.eventSourceColumn()} AS event_time_source
       FROM messages WHERE message_id = ?`
    );
    const records = [];
    for (const input of inputs) {
      const result = insertStmt.run(
        input.conversationId,
        input.seq,
        input.role,
        input.content,
        input.tokenCount,
        input.eventAt?.toISOString() ?? null,
        input.eventAt ? "transcript" : null
      );
      const messageId = Number(result.lastInsertRowid);
      this.indexMessageForFullText(messageId, input.content);
      const row = selectStmt.get(messageId);
      records.push(toMessageRecord(row));
    }
    return records;
  }
  async getMessages(conversationId, opts) {
    const afterSeq = opts?.afterSeq ?? -1;
    const limit = opts?.limit;
    if (limit != null) {
      const rows2 = this.db.prepare(
        `SELECT message_id, conversation_id, seq, role, content, token_count, created_at, ${this.eventTimeColumn()} AS event_at, ${this.eventSourceColumn()} AS event_time_source
         FROM messages
         WHERE conversation_id = ? AND seq > ?
         ORDER BY seq
         LIMIT ?`
      ).all(conversationId, afterSeq, limit);
      return rows2.map(toMessageRecord);
    }
    const rows = this.db.prepare(
      `SELECT message_id, conversation_id, seq, role, content, token_count, created_at, ${this.eventTimeColumn()} AS event_at, ${this.eventSourceColumn()} AS event_time_source
       FROM messages
       WHERE conversation_id = ? AND seq > ?
       ORDER BY seq`
    ).all(conversationId, afterSeq);
    return rows.map(toMessageRecord);
  }
  async getMessageById(messageId) {
    return this.getMessageByIdSync(messageId);
  }
  getMessageByIdSync(messageId) {
    this.messageByIdStatement ??= this.db.prepare(
      `SELECT message_id, conversation_id, seq, role, content, token_count, created_at, ${this.eventTimeColumn()} AS event_at, ${this.eventSourceColumn()} AS event_time_source
       FROM messages WHERE message_id = ?`
    );
    const row = this.messageByIdStatement.get(messageId);
    return row ? toMessageRecord(row) : null;
  }
  async createMessageParts(messageId, parts) {
    if (parts.length === 0) {
      return;
    }
    const stmt = this.db.prepare(
      `INSERT INTO message_parts (
         part_id,
         message_id,
         session_id,
         part_type,
         ordinal,
         text_content,
         tool_call_id,
         tool_name,
         tool_input,
         tool_output,
         metadata
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const part of parts) {
      stmt.run(
        randomUUID(),
        messageId,
        part.sessionId,
        part.partType,
        part.ordinal,
        part.textContent ?? null,
        part.toolCallId ?? null,
        part.toolName ?? null,
        part.toolInput ?? null,
        part.toolOutput ?? null,
        part.metadata ?? null
      );
    }
  }
  /** Messages in one conversation, or in session conversations when none is named. */
  async getMessageCount(conversationId) {
    const row = conversationId == null ? this.db.prepare(this.db.prepare("PRAGMA table_info(conversations)").all().some((column) => column.name === "is_timeline") ? "SELECT (SELECT COUNT(*) FROM messages) - (SELECT COUNT(*) FROM messages WHERE conversation_id = (SELECT conversation_id FROM conversations WHERE is_timeline = 1)) AS count" : "SELECT COUNT(*) AS count FROM messages").get() : this.db.prepare(`SELECT COUNT(*) AS count FROM messages WHERE conversation_id = ?`).get(conversationId);
    return row?.count ?? 0;
  }
  async getMaxSeq(conversationId) {
    const row = this.db.prepare(
      `SELECT COALESCE(MAX(seq), 0) AS max_seq
       FROM messages WHERE conversation_id = ?`
    ).get(conversationId);
    return row?.max_seq ?? 0;
  }
  // ── Search ────────────────────────────────────────────────────────────────
  searchMessagesSync(input) {
    const limit = input.limit ?? 50;
    if (input.mode === "full_text") {
      if (this.fts5Available) {
        try {
          return this.searchFullText(
            input.query,
            limit,
            input.conversationId,
            input.since,
            input.before,
            input.terms,
            input.summaryId
          );
        } catch {
          return this.searchLike(
            input.query,
            limit,
            input.conversationId,
            input.since,
            input.before,
            input.summaryId
          );
        }
      }
      return this.searchLike(input.query, limit, input.conversationId, input.since, input.before, input.summaryId);
    }
    return this.searchRegex(input.query, limit, input.conversationId, input.since, input.before, input.summaryId);
  }
  indexMessageForFullText(messageId, content) {
    if (!this.fts5Available) {
      return;
    }
    try {
      this.db.prepare(`INSERT INTO messages_fts(rowid, content) VALUES (?, ?)`).run(messageId, content);
    } catch {
    }
  }
  searchFullText(query, limit, conversationId, since, before, terms, summaryId) {
    const prepared = prepareFts5Query(query, terms);
    if (!prepared) {
      return [];
    }
    const rows = this.runFullTextMatch(prepared.and, limit, conversationId, since, before, summaryId);
    if (!shouldRetryWithLike(prepared)) {
      return rows;
    }
    if (rows.length < limit) {
      const seen = new Set(rows.map((row) => row.messageId));
      for (const row of this.runFullTextMatch(prepared.or, limit, conversationId, since, before, summaryId)) {
        if (rows.length >= limit) break;
        if (!seen.has(row.messageId)) rows.push(row);
      }
    }
    if (rows.length > 0) {
      return rows;
    }
    return this.searchLikeTerms(prepared, limit, conversationId, since, before, summaryId);
  }
  runFullTextMatch(ftsExpression, limit, conversationId, since, before, summaryId) {
    const where = ["messages_fts MATCH ?"];
    const args = [ftsExpression];
    if (summaryId !== void 0) {
      where.push(`m.message_id IN (SELECT message_id FROM summary_messages WHERE summary_id IN (${SUMMARY_SOURCE_IDS_SQL}))`);
      args.push(summaryId);
    }
    if (conversationId != null) {
      where.push("m.conversation_id = ?");
      args.push(conversationId);
    }
    if (since) {
      where.push("julianday(m.created_at) >= julianday(?)");
      args.push(since.toISOString());
    }
    if (before) {
      where.push("julianday(m.created_at) < julianday(?)");
      args.push(before.toISOString());
    }
    args.push(limit);
    const sql = `SELECT
         m.message_id,
         m.conversation_id,
         m.role,
         snippet(messages_fts, 0, '', '', '...', 32) AS snippet,
         rank,
         m.created_at
       FROM messages_fts
       JOIN messages m ON m.message_id = messages_fts.rowid
       WHERE ${where.join(" AND ")}
       ORDER BY rank
       LIMIT ?`;
    const rows = this.db.prepare(sql).all(...args);
    return byRankThenNewest(rows.map(toSearchResult));
  }
  /** Substring scan OR-ing the prepared terms (vocabulary-mismatch fallback). */
  searchLikeTerms(prepared, limit, conversationId, since, before, summaryId) {
    const plan = likePlanForPreparedQuery(MESSAGE_SEARCH_CONTENT_SQL, prepared);
    if (plan.terms.length === 0) {
      return [];
    }
    const where = [`(${plan.where.join(" OR ")})`];
    const args = [...plan.args];
    if (summaryId !== void 0) {
      where.push(`message_id IN (SELECT message_id FROM summary_messages WHERE summary_id IN (${SUMMARY_SOURCE_IDS_SQL}))`);
      args.push(summaryId);
    }
    if (conversationId != null) {
      where.push("conversation_id = ?");
      args.push(conversationId);
    }
    if (since) {
      where.push("julianday(created_at) >= julianday(?)");
      args.push(since.toISOString());
    }
    if (before) {
      where.push("julianday(created_at) < julianday(?)");
      args.push(before.toISOString());
    }
    args.push(limit);
    const rows = this.db.prepare(
      `SELECT message_id, conversation_id, seq, role, ${MESSAGE_SEARCH_CONTENT_SQL} AS content, token_count, created_at, ${this.eventTimeColumn()} AS event_at, ${this.eventSourceColumn()} AS event_time_source
         FROM messages
         WHERE ${where.join(" AND ")}
         ORDER BY created_at DESC
         LIMIT ?`
    ).all(...args);
    return rows.map((row) => ({
      messageId: row.message_id,
      conversationId: row.conversation_id,
      role: row.role,
      snippet: createFallbackSnippet(row.content, plan.terms),
      createdAt: parseSqliteDate(row.created_at),
      rank: 0
    }));
  }
  searchLike(query, limit, conversationId, since, before, summaryId) {
    const plan = buildLikeSearchPlan(MESSAGE_SEARCH_CONTENT_SQL, query);
    if (plan.terms.length === 0) {
      return [];
    }
    const where = [...plan.where];
    const args = [...plan.args];
    if (summaryId !== void 0) {
      where.push(`message_id IN (SELECT message_id FROM summary_messages WHERE summary_id IN (${SUMMARY_SOURCE_IDS_SQL}))`);
      args.push(summaryId);
    }
    if (conversationId != null) {
      where.push("conversation_id = ?");
      args.push(conversationId);
    }
    if (since) {
      where.push("julianday(created_at) >= julianday(?)");
      args.push(since.toISOString());
    }
    if (before) {
      where.push("julianday(created_at) < julianday(?)");
      args.push(before.toISOString());
    }
    args.push(limit);
    const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const rows = this.db.prepare(
      `SELECT message_id, conversation_id, seq, role, ${MESSAGE_SEARCH_CONTENT_SQL} AS content, token_count, created_at, ${this.eventTimeColumn()} AS event_at, ${this.eventSourceColumn()} AS event_time_source
         FROM messages
         ${whereClause}
         ORDER BY created_at DESC
         LIMIT ?`
    ).all(...args);
    return rows.map((row) => ({
      messageId: row.message_id,
      conversationId: row.conversation_id,
      role: row.role,
      snippet: createFallbackSnippet(row.content, plan.terms),
      createdAt: parseSqliteDate(row.created_at),
      rank: 0
    }));
  }
  searchRegex(pattern, limit, conversationId, since, before, summaryId) {
    const re = validateRegex(pattern);
    const where = [];
    const args = [];
    if (summaryId !== void 0) {
      where.push(`message_id IN (SELECT message_id FROM summary_messages WHERE summary_id IN (${SUMMARY_SOURCE_IDS_SQL}))`);
      args.push(summaryId);
    }
    if (conversationId != null) {
      where.push("conversation_id = ?");
      args.push(conversationId);
    }
    if (since) {
      where.push("julianday(created_at) >= julianday(?)");
      args.push(since.toISOString());
    }
    if (before) {
      where.push("julianday(created_at) < julianday(?)");
      args.push(before.toISOString());
    }
    const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const rows = this.db.prepare(
      `SELECT message_id, conversation_id, seq, role, ${MESSAGE_SEARCH_CONTENT_SQL} AS content, token_count, created_at, ${this.eventTimeColumn()} AS event_at, ${this.eventSourceColumn()} AS event_time_source
         FROM messages
         ${whereClause}
         ORDER BY created_at DESC`
    ).all(...args);
    const results = [];
    for (const row of rows) {
      if (results.length >= limit) {
        break;
      }
      const match = re.exec(row.content);
      if (match) {
        results.push({
          messageId: row.message_id,
          conversationId: row.conversation_id,
          role: row.role,
          snippet: match[0],
          createdAt: parseSqliteDate(row.created_at),
          rank: 0
        });
      }
    }
    return results;
  }
};

// ../_research/lcm-full-20261021/src/store/summary-store.ts
var TIME_BOUNDS_PAGE_SIZE = 128;
var CONTEXT_PAGE_SIZE = 128;
function toSummaryRecord(row) {
  let fileIds = [];
  try {
    fileIds = JSON.parse(row.file_ids);
  } catch {
  }
  return {
    summaryId: row.summary_id,
    conversationId: row.conversation_id,
    kind: row.kind,
    depth: row.depth,
    content: row.content,
    tokenCount: row.token_count,
    fileIds,
    earliestAt: row.earliest_at ? parseSqliteDate(row.earliest_at) : null,
    latestAt: row.latest_at ? parseSqliteDate(row.latest_at) : null,
    hasEventTime: row.has_event_time === 1,
    descendantCount: typeof row.descendant_count === "number" && Number.isFinite(row.descendant_count) && row.descendant_count >= 0 ? Math.floor(row.descendant_count) : 0,
    descendantTokenCount: typeof row.descendant_token_count === "number" && Number.isFinite(row.descendant_token_count) && row.descendant_token_count >= 0 ? Math.floor(row.descendant_token_count) : 0,
    sourceMessageTokenCount: typeof row.source_message_token_count === "number" && Number.isFinite(row.source_message_token_count) && row.source_message_token_count >= 0 ? Math.floor(row.source_message_token_count) : 0,
    createdAt: parseSqliteDate(row.created_at)
  };
}
function toContextItemRecord(row) {
  return {
    conversationId: row.conversation_id,
    ordinal: row.ordinal,
    itemType: row.item_type,
    messageId: row.message_id,
    summaryId: row.summary_id,
    createdAt: parseSqliteDate(row.created_at)
  };
}
function toContextWindowItem(row) {
  return { ordinal: row.ordinal, itemType: row.item_type, role: row.role, content: row.content, summaryId: row.summary_id };
}
function toSearchResult2(row) {
  return {
    summaryId: row.summary_id,
    conversationId: row.conversation_id,
    kind: row.kind,
    snippet: row.snippet,
    createdAt: parseSqliteDate(row.created_at),
    rank: row.rank
  };
}
function toLargeFileRecord(row) {
  return {
    fileId: row.file_id,
    conversationId: row.conversation_id,
    fileName: row.file_name,
    mimeType: row.mime_type,
    byteSize: row.byte_size,
    storageUri: row.storage_uri,
    explorationSummary: row.exploration_summary,
    createdAt: parseSqliteDate(row.created_at)
  };
}
var SummaryStore = class {
  constructor(db, options) {
    this.db = db;
    this.fts5Available = options?.fts5Available ?? true;
    this.includeStale = options?.includeStale ?? true;
  }
  db;
  getCommitReferences(summaryId) {
    return new CommitStore(this.db).forSummary(summaryId);
  }
  fts5Available;
  includeStale;
  /** Covering leaf and condensed summaries for a bounded set of grep matches. */
  coveringSummaryIds(messageIds) {
    const result = /* @__PURE__ */ new Map();
    if (messageIds.length === 0) return result;
    const rows = this.db.prepare(`
      WITH RECURSIVE coverage(message_id, summary_id) AS (
        SELECT message_id, summary_id FROM summary_messages
        WHERE message_id IN (SELECT value FROM json_each(?))
        UNION
        SELECT coverage.message_id, sp.summary_id FROM coverage
        JOIN summary_parents sp ON sp.parent_summary_id = coverage.summary_id
      )
      SELECT coverage.message_id, coverage.summary_id FROM coverage
      JOIN summaries s ON s.summary_id = coverage.summary_id
      ORDER BY s.depth, coverage.summary_id
    `).all(JSON.stringify(messageIds));
    for (const row of rows) {
      const ids = result.get(row.message_id) ?? [];
      ids.push(row.summary_id);
      result.set(row.message_id, ids);
    }
    return result;
  }
  // ── Summary CRUD ──────────────────────────────────────────────────────────
  /** Summaries neither present in context nor used as source by another summary. */
  getOrphanSummaryIds() {
    const hasTimeline = this.db.prepare("PRAGMA table_info(conversations)").all().some((column) => column.name === "is_timeline");
    const rows = this.db.prepare(`
      SELECT s.summary_id FROM summaries s
       WHERE ${hasTimeline ? "NOT EXISTS (SELECT 1 FROM conversations owner WHERE owner.conversation_id = s.conversation_id AND owner.is_timeline = 1)" : "1"}
         AND NOT EXISTS (SELECT 1 FROM context_items c WHERE c.summary_id = s.summary_id)
         AND NOT EXISTS (SELECT 1 FROM summary_parents p
           ${hasTimeline ? "JOIN summaries consumer ON consumer.summary_id = p.summary_id JOIN conversations owner ON owner.conversation_id = consumer.conversation_id" : ""}
           WHERE p.parent_summary_id = s.summary_id ${hasTimeline ? "AND owner.is_timeline = 0" : ""})
       ORDER BY s.summary_id
    `).all();
    return rows.map((row) => row.summary_id);
  }
  async insertSummary(input) {
    return this.insertSummarySync(input);
  }
  insertSummarySync(input) {
    const conversation = this.db.prepare("SELECT session_id FROM conversations WHERE conversation_id = ?").get(input.conversationId);
    if (conversation && new WorkerStore(this.db).excluded(conversation.session_id)) throw new Error("Worker session is excluded from compaction");
    const fileIds = JSON.stringify(input.fileIds ?? []);
    const earliestAt = input.earliestAt instanceof Date ? input.earliestAt.toISOString() : null;
    const latestAt = input.latestAt instanceof Date ? input.latestAt.toISOString() : null;
    const descendantCount = typeof input.descendantCount === "number" && Number.isFinite(input.descendantCount) && input.descendantCount >= 0 ? Math.floor(input.descendantCount) : 0;
    const descendantTokenCount = typeof input.descendantTokenCount === "number" && Number.isFinite(input.descendantTokenCount) && input.descendantTokenCount >= 0 ? Math.floor(input.descendantTokenCount) : 0;
    const sourceMessageTokenCount = typeof input.sourceMessageTokenCount === "number" && Number.isFinite(input.sourceMessageTokenCount) && input.sourceMessageTokenCount >= 0 ? Math.floor(input.sourceMessageTokenCount) : 0;
    const depth = typeof input.depth === "number" && Number.isFinite(input.depth) && input.depth >= 0 ? Math.floor(input.depth) : input.kind === "leaf" ? 0 : 1;
    this.db.prepare(
      `INSERT INTO summaries (
          summary_id,
          conversation_id,
          kind,
          depth,
          content,
          token_count,
          file_ids,
          earliest_at,
          latest_at,
          has_event_time,
          descendant_count,
          descendant_token_count,
          source_message_token_count
        )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      input.summaryId,
      input.conversationId,
      input.kind,
      depth,
      input.content,
      input.tokenCount,
      fileIds,
      earliestAt,
      latestAt,
      Number(input.hasEventTime ?? false),
      descendantCount,
      descendantTokenCount,
      sourceMessageTokenCount
    );
    const row = this.db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, content, token_count, file_ids,
                earliest_at, latest_at, descendant_count, created_at
                , descendant_token_count, source_message_token_count, has_event_time
       FROM summaries WHERE summary_id = ?`
    ).get(input.summaryId);
    if (!this.fts5Available) {
      return toSummaryRecord(row);
    }
    try {
      this.db.prepare(`INSERT INTO summaries_fts(summary_id, content) VALUES (?, ?)`).run(input.summaryId, input.content);
    } catch {
    }
    return toSummaryRecord(row);
  }
  async getSummary(summaryId) {
    return this.getSummarySync(summaryId);
  }
  getSummarySync(summaryId) {
    const row = this.db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, content, token_count, file_ids,
                earliest_at, latest_at, descendant_count, created_at
                , descendant_token_count, source_message_token_count, has_event_time
       FROM summaries WHERE summary_id = ?`
    ).get(summaryId);
    return row ? toSummaryRecord(row) : null;
  }
  async getSummariesByConversation(conversationId) {
    const rows = this.db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, content, token_count, file_ids,
                earliest_at, latest_at, descendant_count, created_at
                , descendant_token_count, source_message_token_count, has_event_time
       FROM summaries
       WHERE conversation_id = ?
       ORDER BY created_at`
    ).all(conversationId);
    return rows.map(toSummaryRecord);
  }
  /** A conversation's summaries, the most condensed and then the newest first. */
  async summariesDeepestFirst(conversationId, limit) {
    const rows = this.db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, content, token_count, file_ids,
                earliest_at, latest_at, descendant_count, created_at
                , descendant_token_count, source_message_token_count, has_event_time
       FROM summaries
       WHERE conversation_id = ?
       ORDER BY depth DESC, created_at DESC
       LIMIT ?`
    ).all(conversationId, limit);
    return rows.map(toSummaryRecord);
  }
  /** The newest summaries across every conversation. */
  async listRecent(limit) {
    const rows = this.db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, content, token_count, file_ids,
                earliest_at, latest_at, descendant_count, created_at
                , descendant_token_count, source_message_token_count, has_event_time
       FROM summaries
       ORDER BY created_at DESC
       LIMIT ?`
    ).all(limit);
    return rows.map(toSummaryRecord);
  }
  // ── Lineage ───────────────────────────────────────────────────────────────
  /** Known bounds from direct sources' persisted metadata, without reading their descendants. */
  getSourceEventTimeBounds(summaryIds) {
    const rows = this.db.prepare(`SELECT s.earliest_at, s.latest_at FROM summaries s
      WHERE s.summary_id IN (SELECT value FROM json_each(?)) AND s.has_event_time = 1`).all(JSON.stringify(summaryIds));
    if (!rows.length) return null;
    return {
      earliestAt: new Date(Math.min(...rows.map((row) => parseSqliteDate(row.earliest_at).getTime()))),
      latestAt: new Date(Math.max(...rows.map((row) => parseSqliteDate(row.latest_at).getTime())))
    };
  }
  /** Recompute leaves before their condensed descendants, yielding between bounded pages. */
  async recomputeTimeBounds(conversationId) {
    let depth = -1;
    let id = "";
    for (; ; ) {
      const page = this.db.prepare(`SELECT summary_id, depth, kind FROM summaries WHERE conversation_id = ?
        AND (depth, summary_id) > (?, ?) ORDER BY depth, summary_id LIMIT ${TIME_BOUNDS_PAGE_SIZE}`).all(conversationId, depth, id);
      for (const summary of page) {
        const range = summary.kind === "leaf" ? this.db.prepare(`SELECT COALESCE(MIN(julianday(m.event_at)), MIN(julianday(m.created_at))) first,
              COALESCE(MAX(julianday(m.event_at)), MAX(julianday(m.created_at))) last, COUNT(m.event_at) > 0 known
              FROM summary_messages sm JOIN messages m USING(message_id) WHERE sm.summary_id = ?`).get(summary.summary_id) : this.db.prepare(`SELECT COALESCE(MIN(CASE WHEN s.has_event_time = 1 THEN julianday(s.earliest_at) END),
                MIN(julianday(COALESCE(s.earliest_at, s.created_at)))) first,
              COALESCE(MAX(CASE WHEN s.has_event_time = 1 THEN julianday(s.latest_at) END),
                MAX(julianday(COALESCE(s.latest_at, s.created_at)))) last, COALESCE(MAX(s.has_event_time), 0) known
              FROM summary_parents p JOIN summaries s ON s.summary_id = p.parent_summary_id WHERE p.summary_id = ?`).get(summary.summary_id);
        const bounds = range;
        this.db.prepare(`UPDATE summaries
          SET earliest_at = COALESCE(strftime('%Y-%m-%dT%H:%M:%fZ', ?), created_at),
            latest_at = COALESCE(strftime('%Y-%m-%dT%H:%M:%fZ', ?), created_at), has_event_time = ?
          WHERE summary_id = ? AND (julianday(earliest_at) IS NOT ? OR julianday(latest_at) IS NOT ? OR has_event_time != ?)`).run(bounds.first, bounds.last, bounds.known, summary.summary_id, bounds.first, bounds.last, bounds.known);
      }
      await yieldToEventLoop();
      if (page.length < TIME_BOUNDS_PAGE_SIZE) return;
      depth = page.at(-1).depth;
      id = page.at(-1).summary_id;
    }
  }
  async linkSummaryToMessages(summaryId, messageIds) {
    for (let offset = 0; offset < messageIds.length; offset += CONTEXT_PAGE_SIZE) {
      this.linkSummaryToMessagesSync(summaryId, messageIds.slice(offset, offset + CONTEXT_PAGE_SIZE), offset);
      await yieldToEventLoop();
    }
  }
  linkSummaryToMessagesSync(summaryId, messageIds, ordinalOffset = 0) {
    if (messageIds.length === 0) {
      return;
    }
    const stmt = this.db.prepare(
      `INSERT INTO summary_messages (summary_id, message_id, ordinal)
       VALUES (?, ?, ?)
       ON CONFLICT (summary_id, message_id) DO NOTHING`
    );
    for (let idx = 0; idx < messageIds.length; idx++) {
      stmt.run(summaryId, messageIds[idx], ordinalOffset + idx);
    }
  }
  async linkSummaryToParents(summaryId, parentSummaryIds) {
    for (let offset = 0; offset < parentSummaryIds.length; offset += CONTEXT_PAGE_SIZE) {
      this.linkSummaryToParentsSync(summaryId, parentSummaryIds.slice(offset, offset + CONTEXT_PAGE_SIZE), offset);
      await yieldToEventLoop();
    }
  }
  linkSummaryToParentsSync(summaryId, parentSummaryIds, ordinalOffset = 0) {
    if (parentSummaryIds.length === 0) {
      return;
    }
    const stmt = this.db.prepare(
      `INSERT INTO summary_parents (summary_id, parent_summary_id, ordinal)
       VALUES (?, ?, ?)
       ON CONFLICT (summary_id, parent_summary_id) DO NOTHING`
    );
    for (let idx = 0; idx < parentSummaryIds.length; idx++) {
      stmt.run(summaryId, parentSummaryIds[idx], ordinalOffset + idx);
    }
  }
  async getSummaryMessages(summaryId) {
    const rows = this.db.prepare(
      `SELECT message_id FROM summary_messages
       WHERE summary_id = ?
       ORDER BY ordinal`
    ).all(summaryId);
    return rows.map((r) => r.message_id);
  }
  async getSummaryChildren(parentSummaryId) {
    const rows = this.db.prepare(
      `SELECT s.summary_id, s.conversation_id, s.kind, s.depth, s.content, s.token_count,
                s.file_ids, s.earliest_at, s.latest_at, s.descendant_count, s.created_at
                , s.descendant_token_count, s.source_message_token_count, s.has_event_time
       FROM summaries s
       JOIN summary_parents sp ON sp.summary_id = s.summary_id
       WHERE sp.parent_summary_id = ?
       ORDER BY sp.ordinal`
    ).all(parentSummaryId);
    return rows.map(toSummaryRecord);
  }
  async getSummaryParents(summaryId) {
    const rows = this.db.prepare(
      `SELECT s.summary_id, s.conversation_id, s.kind, s.depth, s.content, s.token_count,
                s.file_ids, s.earliest_at, s.latest_at, s.descendant_count, s.created_at
                , s.descendant_token_count, s.source_message_token_count, s.has_event_time
       FROM summaries s
       JOIN summary_parents sp ON sp.parent_summary_id = s.summary_id
       WHERE sp.summary_id = ?
       ORDER BY sp.ordinal`
    ).all(summaryId);
    return rows.map(toSummaryRecord);
  }
  async getSummarySubtree(summaryId) {
    const rows = this.db.prepare(
      `WITH RECURSIVE subtree(summary_id, parent_summary_id, depth_from_root, path) AS (
           SELECT ?, NULL, 0, ''
           UNION ALL
           SELECT
             sp.parent_summary_id,
             sp.summary_id,
             subtree.depth_from_root + 1,
             CASE
               WHEN subtree.path = '' THEN printf('%04d', sp.ordinal)
               ELSE subtree.path || '.' || printf('%04d', sp.ordinal)
             END
           FROM summary_parents sp
           JOIN subtree ON sp.summary_id = subtree.summary_id
         )
         SELECT
           s.summary_id,
           s.conversation_id,
           s.kind,
           s.depth,
           s.content,
           s.token_count,
           s.file_ids,
           s.earliest_at,
           s.latest_at,
           s.descendant_count,
           s.descendant_token_count,
           s.source_message_token_count, s.has_event_time,
           s.created_at,
           subtree.depth_from_root,
           subtree.parent_summary_id,
           subtree.path,
           (
             SELECT COUNT(*) FROM summary_parents sp2
             WHERE sp2.summary_id = s.summary_id
           ) AS child_count
         FROM subtree
         JOIN summaries s ON s.summary_id = subtree.summary_id
         ORDER BY subtree.depth_from_root ASC, subtree.path ASC, s.created_at ASC`
    ).all(summaryId);
    const seen = /* @__PURE__ */ new Set();
    const output = [];
    for (const row of rows) {
      if (seen.has(row.summary_id)) {
        continue;
      }
      seen.add(row.summary_id);
      output.push({
        ...toSummaryRecord(row),
        depthFromRoot: Math.max(0, Math.floor(row.depth_from_root ?? 0)),
        parentSummaryId: row.parent_summary_id ?? null,
        path: typeof row.path === "string" ? row.path : "",
        childCount: typeof row.child_count === "number" && Number.isFinite(row.child_count) ? Math.max(0, Math.floor(row.child_count)) : 0
      });
    }
    return output;
  }
  // ── Context items ─────────────────────────────────────────────────────────
  async getContextItems(conversationId, options) {
    const rows = this.db.prepare(
      `SELECT conversation_id, ordinal, item_type, message_id, summary_id, created_at
       FROM context_items
       WHERE conversation_id = ? ${options?.afterOrdinal != null ? "AND ordinal > ?" : ""}
       ORDER BY ordinal`
    ).all(...options?.afterOrdinal != null ? [conversationId, options.afterOrdinal] : [conversationId]);
    return rows.map(toContextItemRecord);
  }
  /**
   * The end of the context as a restore replays it: the last `limit`
   * summaries and the last `limit` user/assistant messages among the context
   * items, in context order. A conversation captured before context items
   * were materialised has none; its last `limit` user/assistant messages
   * stand in, in seq order.
   */
  async readContextWindow(conversationId, limit, options = {}) {
    if (options.complete) {
      const hasContext = this.db.prepare("SELECT 1 FROM context_items WHERE conversation_id = ? LIMIT 1").get(conversationId);
      const rows = this.db.prepare(hasContext ? `
        SELECT ci.ordinal, ci.item_type, ci.summary_id AS summaryId, m.message_id AS messageId,
               m.seq, m.role, COALESCE(m.content, s.content) AS content
        FROM context_items ci
        LEFT JOIN messages m ON ci.item_type = 'message' AND m.message_id = ci.message_id AND m.conversation_id = ci.conversation_id
        LEFT JOIN summaries s ON ci.item_type = 'summary' AND s.summary_id = ci.summary_id AND s.conversation_id = ci.conversation_id
        WHERE ci.conversation_id = ? AND COALESCE(m.content, s.content) IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM message_parts p WHERE p.message_id = m.message_id AND p.part_type = 'compaction')
        ORDER BY ci.ordinal` : `
        SELECT m.seq AS ordinal, 'message' AS item_type, NULL AS summaryId, m.message_id AS messageId,
               m.seq, m.role, m.content FROM messages m WHERE m.conversation_id = ?
          AND NOT EXISTS (SELECT 1 FROM message_parts p WHERE p.message_id = m.message_id AND p.part_type = 'compaction')
        ORDER BY m.seq`).all(conversationId);
      return rows.map(({ item_type, ...row }) => ({ ...row, itemType: item_type }));
    }
    const contextRows = this.db.prepare(
      `WITH ranked AS (
           SELECT ci.ordinal, ci.item_type, ci.summary_id, m.role, COALESCE(m.content, s.content) AS content,
                  ROW_NUMBER() OVER (PARTITION BY ci.item_type ORDER BY ci.ordinal DESC) AS item_rank
           FROM context_items ci
           LEFT JOIN messages m ON ci.item_type = 'message' AND m.message_id = ci.message_id
           LEFT JOIN summaries s ON ci.item_type = 'summary' AND s.summary_id = ci.summary_id
           WHERE ci.conversation_id = ?
             AND ((ci.item_type = 'summary' AND s.content IS NOT NULL)
               OR (ci.item_type = 'message' AND m.role IN ('user', 'assistant') AND m.content IS NOT NULL))
         )
         SELECT ordinal, item_type, summary_id, role, content
         FROM ranked
         WHERE item_rank <= ?
         ORDER BY ordinal`
    ).all(conversationId, limit);
    if (contextRows.length > 0) return contextRows.map(toContextWindowItem);
    const messageRows = this.db.prepare(
      `SELECT seq AS ordinal, 'message' AS item_type, NULL AS summary_id, role, content
         FROM messages
         WHERE conversation_id = ? AND role IN ('user', 'assistant')
         ORDER BY seq DESC
         LIMIT ?`
    ).all(conversationId, limit);
    return messageRows.reverse().map(toContextWindowItem);
  }
  /** Exact source coverage of complete rendered items; malformed lineage never proves coverage. */
  async readContextCoverage(conversationId, items) {
    const capturedMessageIds = this.db.prepare(`SELECT m.message_id FROM messages m WHERE m.conversation_id = ?
      AND NOT EXISTS (SELECT 1 FROM message_parts p WHERE p.message_id = m.message_id AND p.part_type = 'compaction')
      ORDER BY m.seq`).all(conversationId).map((r) => r.message_id);
    const captured = new Set(capturedMessageIds);
    const activeRoots = new Set((await this.getContextItems(conversationId)).map((i2) => i2.summaryId).filter(Boolean));
    const parents = this.db.prepare("SELECT parent_summary_id FROM summary_parents WHERE summary_id = ? ORDER BY ordinal");
    const messages = this.db.prepare("SELECT message_id FROM summary_messages WHERE summary_id = ? ORDER BY ordinal");
    const memo = /* @__PURE__ */ new Map();
    const visiting = /* @__PURE__ */ new Set();
    const renderedRoots = new Set(items.filter((i2) => i2.itemType === "summary").map((i2) => i2.summaryId));
    const dangling = this.db.prepare(`SELECT 1 FROM context_items ci WHERE ci.conversation_id = ? AND (
      (ci.item_type = 'message' AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.message_id = ci.message_id AND m.conversation_id = ci.conversation_id)) OR
      (ci.item_type = 'summary' AND NOT EXISTS (SELECT 1 FROM summaries s WHERE s.summary_id = ci.summary_id AND s.conversation_id = ci.conversation_id))) LIMIT 1`).get(conversationId);
    let valid = !dangling && [...activeRoots].every((id) => renderedRoots.has(id));
    const visit = async (id) => {
      if (visiting.has(id)) {
        valid = false;
        return /* @__PURE__ */ new Set();
      }
      const known = memo.get(id);
      if (known) return known;
      const summary = await this.getSummary(id);
      if (!summary || !summary.content.trim() || summary.conversationId !== conversationId) {
        valid = false;
        return /* @__PURE__ */ new Set();
      }
      visiting.add(id);
      const source = new Set(messages.all(id).map((r) => r.message_id));
      if ([...source].some((messageId) => !captured.has(messageId))) valid = false;
      const parentIds = parents.all(id).map((r) => r.parent_summary_id);
      if (source.size === 0 && parentIds.length === 0) valid = false;
      for (const parentId of parentIds) for (const messageId of await visit(parentId)) source.add(messageId);
      visiting.delete(id);
      memo.set(id, source);
      await yieldToEventLoop();
      return source;
    };
    const renderedMessageIds = items.flatMap((i2) => i2.itemType === "message" && i2.messageId != null ? [i2.messageId] : []);
    if (renderedMessageIds.some((id) => !captured.has(id))) valid = false;
    const covered = new Set(renderedMessageIds);
    const summaryCoverage = [];
    for (const item of items) {
      if (item.itemType !== "summary" || !item.summaryId) continue;
      if (!activeRoots.has(item.summaryId)) valid = false;
      const ids = [...await visit(item.summaryId)].sort((a, b) => a - b);
      summaryCoverage.push({ summaryId: item.summaryId, messageIds: ids });
      for (const id of ids) covered.add(id);
    }
    return {
      capturedMessageIds,
      renderedMessageIds,
      summaryCoverage,
      uncoveredMessageIds: capturedMessageIds.filter((id) => !covered.has(id)),
      valid
    };
  }
  async getDistinctDepthsInContext(conversationId, options) {
    const maxOrdinalExclusive = options?.maxOrdinalExclusive;
    const useOrdinalBound = typeof maxOrdinalExclusive === "number" && Number.isFinite(maxOrdinalExclusive) && maxOrdinalExclusive !== Infinity;
    const sql = useOrdinalBound ? `SELECT DISTINCT s.depth
         FROM context_items ci
         JOIN summaries s ON s.summary_id = ci.summary_id
         WHERE ci.conversation_id = ?
           AND ci.item_type = 'summary'
           AND ci.ordinal < ?
         ORDER BY s.depth ASC` : `SELECT DISTINCT s.depth
         FROM context_items ci
         JOIN summaries s ON s.summary_id = ci.summary_id
         WHERE ci.conversation_id = ?
           AND ci.item_type = 'summary'
         ORDER BY s.depth ASC`;
    const rows = useOrdinalBound ? this.db.prepare(sql).all(conversationId, Math.floor(maxOrdinalExclusive)) : this.db.prepare(sql).all(conversationId);
    return rows.map((row) => row.depth);
  }
  /** How many summaries a conversation holds, or session summaries when none is named. */
  async countSummaries(conversationId) {
    const row = conversationId == null ? this.db.prepare(this.db.prepare("PRAGMA table_info(conversations)").all().some((column) => column.name === "is_timeline") ? "SELECT (SELECT COUNT(*) FROM summaries) - (SELECT COUNT(*) FROM summaries WHERE conversation_id = (SELECT conversation_id FROM conversations WHERE is_timeline = 1)) AS n" : "SELECT COUNT(*) AS n FROM summaries").get() : this.db.prepare(`SELECT COUNT(*) AS n FROM summaries WHERE conversation_id = ?`).get(conversationId);
    return row.n;
  }
  /**
   * Drop every summary in a conversation and rebuild context_items from its
   * messages, in seq order.
   *
   * This is sound because context_items is a derived view: compaction only
   * rewrites it, never deletes messages, so nothing is lost that cannot be
   * re-derived. Callers use it to undo compaction wholesale rather than
   * unpicking individual summaries.
   *
   * Compaction-event messages are dropped and excluded from the rebuild — they
   * describe summaries that no longer exist, and have never been context items.
   *
   * Returns the number of summaries removed.
   */
  async resetConversationContext(conversationId) {
    this.db.exec("BEGIN");
    try {
      const summaryRows = this.db.prepare(`SELECT summary_id FROM summaries WHERE conversation_id = ?`).all(conversationId);
      const summaryIds = summaryRows.map((row) => row.summary_id);
      if (summaryIds.length > 0) {
        const placeholders = summaryIds.map(() => "?").join(", ");
        this.db.prepare(`DELETE FROM summary_messages WHERE summary_id IN (${placeholders})`).run(...summaryIds);
        this.db.prepare(
          `DELETE FROM summary_parents
             WHERE summary_id IN (${placeholders})
                OR parent_summary_id IN (${placeholders})`
        ).run(...summaryIds, ...summaryIds);
      }
      this.db.prepare(`DELETE FROM context_items WHERE conversation_id = ?`).run(conversationId);
      this.db.prepare(`DELETE FROM summaries WHERE conversation_id = ?`).run(conversationId);
      const eventRows = this.db.prepare(
        `SELECT m.message_id FROM messages m
           WHERE m.conversation_id = ?
             AND EXISTS (
               SELECT 1 FROM message_parts p
               WHERE p.message_id = m.message_id AND p.part_type = 'compaction'
             )`
      ).all(conversationId);
      const eventMessageIds = eventRows.map((row) => row.message_id);
      if (eventMessageIds.length > 0) {
        const placeholders = eventMessageIds.map(() => "?").join(", ");
        this.db.prepare(`DELETE FROM messages WHERE message_id IN (${placeholders})`).run(...eventMessageIds);
      }
      this.db.prepare(
        `INSERT INTO context_items (conversation_id, ordinal, item_type, message_id)
           SELECT ?, ROW_NUMBER() OVER (ORDER BY m.seq) - 1, 'message', m.message_id
           FROM messages m
           WHERE m.conversation_id = ?
             AND NOT EXISTS (
               SELECT 1 FROM message_parts p
               WHERE p.message_id = m.message_id AND p.part_type = 'compaction'
             )
           ORDER BY m.seq`
      ).run(conversationId, conversationId);
      this.db.exec("COMMIT");
      if (this.fts5Available) {
        if (summaryIds.length > 0) {
          const placeholders = summaryIds.map(() => "?").join(", ");
          try {
            this.db.prepare(`DELETE FROM summaries_fts WHERE summary_id IN (${placeholders})`).run(...summaryIds);
          } catch {
          }
        }
        if (eventMessageIds.length > 0) {
          const placeholders = eventMessageIds.map(() => "?").join(", ");
          try {
            this.db.prepare(`DELETE FROM messages_fts WHERE rowid IN (${placeholders})`).run(...eventMessageIds);
          } catch {
          }
        }
      }
      return summaryIds.length;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }
  async appendContextMessages(conversationId, messageIds) {
    if (messageIds.length === 0) {
      return;
    }
    const row = this.db.prepare(
      `SELECT COALESCE(MAX(ordinal), -1) AS max_ordinal
       FROM context_items WHERE conversation_id = ?`
    ).get(conversationId);
    const baseOrdinal = row.max_ordinal + 1;
    const stmt = this.db.prepare(
      `INSERT INTO context_items (conversation_id, ordinal, item_type, message_id)
       VALUES (?, ?, 'message', ?)`
    );
    for (let idx = 0; idx < messageIds.length; idx++) {
      stmt.run(conversationId, baseOrdinal + idx, messageIds[idx]);
    }
  }
  async replaceContextRangeWithSummary(input) {
    const { conversationId, startOrdinal, endOrdinal, summaryId } = input;
    this.db.exec("BEGIN");
    try {
      this.db.prepare(
        `DELETE FROM context_items
         WHERE conversation_id = ?
           AND ordinal >= ?
           AND ordinal <= ?`
      ).run(conversationId, startOrdinal, endOrdinal);
      this.db.prepare(
        `INSERT INTO context_items (conversation_id, ordinal, item_type, summary_id)
         VALUES (?, ?, 'summary', ?)`
      ).run(conversationId, startOrdinal, summaryId);
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }
  async getContextTokenCount(conversationId) {
    const row = this.db.prepare(
      `SELECT COALESCE(SUM(token_count), 0) AS total
       FROM (
         SELECT m.token_count
         FROM context_items ci
         JOIN messages m ON m.message_id = ci.message_id
         WHERE ci.conversation_id = ?
           AND ci.item_type = 'message'

         UNION ALL

         SELECT s.token_count
         FROM context_items ci
         JOIN summaries s ON s.summary_id = ci.summary_id
         WHERE ci.conversation_id = ?
           AND ci.item_type = 'summary'
       ) sub`
    ).get(conversationId, conversationId);
    return row?.total ?? 0;
  }
  // ── Search ────────────────────────────────────────────────────────────────
  searchSummariesSync(input) {
    const limit = input.limit ?? 50;
    if (input.mode === "full_text") {
      if (this.fts5Available) {
        try {
          return this.searchFullText(
            input.query,
            limit,
            input.conversationId,
            input.since,
            input.before,
            input.terms,
            input.summaryId
          );
        } catch {
          return this.searchLike(
            input.query,
            limit,
            input.conversationId,
            input.since,
            input.before,
            input.summaryId
          );
        }
      }
      return this.searchLike(input.query, limit, input.conversationId, input.since, input.before, input.summaryId);
    }
    return this.searchRegex(input.query, limit, input.conversationId, input.since, input.before, input.summaryId);
  }
  searchFullText(query, limit, conversationId, since, before, terms, summaryId) {
    const prepared = prepareFts5Query(query, terms);
    if (!prepared) {
      return [];
    }
    const rows = this.runFullTextMatch(prepared.and, limit, conversationId, since, before, summaryId);
    if (!shouldRetryWithLike(prepared)) {
      return rows;
    }
    if (rows.length < limit) {
      const seen = new Set(rows.map((row) => row.summaryId));
      for (const row of this.runFullTextMatch(prepared.or, limit, conversationId, since, before, summaryId)) {
        if (rows.length >= limit) break;
        if (!seen.has(row.summaryId)) rows.push(row);
      }
    }
    if (rows.length > 0) {
      return rows;
    }
    return this.searchLikeTerms(prepared, limit, conversationId, since, before, summaryId);
  }
  timelinePredicate(column = "summary_id") {
    return this.includeStale ? [] : [`NOT EXISTS (SELECT 1 FROM timeline_nodes tn WHERE tn.summary_id = ${column} AND tn.stale_reason IS NOT NULL)`];
  }
  runFullTextMatch(ftsExpression, limit, conversationId, since, before, summaryId) {
    const where = ["summaries_fts MATCH ?", ...this.timelinePredicate("s.summary_id")];
    const args = [ftsExpression];
    if (summaryId !== void 0) {
      where.push(`s.summary_id IN (${SUMMARY_SOURCE_IDS_SQL})`);
      args.push(summaryId);
    }
    if (conversationId != null) {
      where.push("s.conversation_id = ?");
      args.push(conversationId);
    }
    if (since) {
      where.push("julianday(s.created_at) >= julianday(?)");
      args.push(since.toISOString());
    }
    if (before) {
      where.push("julianday(s.created_at) < julianday(?)");
      args.push(before.toISOString());
    }
    args.push(limit);
    const sql = `SELECT
         summaries_fts.summary_id,
         s.conversation_id,
         s.kind,
         snippet(summaries_fts, 1, '', '', '...', 32) AS snippet,
         rank,
         s.created_at
       FROM summaries_fts
       JOIN summaries s ON s.summary_id = summaries_fts.summary_id
       WHERE ${where.join(" AND ")}
       ORDER BY rank
       LIMIT ?`;
    const rows = this.db.prepare(sql).all(...args);
    return byRankThenNewest(rows.map(toSearchResult2));
  }
  /** Substring scan OR-ing the prepared terms (vocabulary-mismatch fallback). */
  searchLikeTerms(prepared, limit, conversationId, since, before, summaryId) {
    const plan = likePlanForPreparedQuery("content", prepared);
    if (plan.terms.length === 0) {
      return [];
    }
    const where = [`(${plan.where.join(" OR ")})`, ...this.timelinePredicate("summaries.summary_id")];
    const args = [...plan.args];
    if (summaryId !== void 0) {
      where.push(`summary_id IN (${SUMMARY_SOURCE_IDS_SQL})`);
      args.push(summaryId);
    }
    if (conversationId != null) {
      where.push("conversation_id = ?");
      args.push(conversationId);
    }
    if (since) {
      where.push("julianday(created_at) >= julianday(?)");
      args.push(since.toISOString());
    }
    if (before) {
      where.push("julianday(created_at) < julianday(?)");
      args.push(before.toISOString());
    }
    args.push(limit);
    const rows = this.db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, content, token_count, file_ids,
                earliest_at, latest_at, descendant_count, descendant_token_count,
                source_message_token_count, has_event_time, created_at
         FROM summaries
         WHERE ${where.join(" AND ")}
         ORDER BY created_at DESC
         LIMIT ?`
    ).all(...args);
    return rows.map((row) => ({
      summaryId: row.summary_id,
      conversationId: row.conversation_id,
      kind: row.kind,
      snippet: createFallbackSnippet(row.content, plan.terms),
      createdAt: parseSqliteDate(row.created_at),
      rank: 0
    }));
  }
  searchLike(query, limit, conversationId, since, before, summaryId) {
    const plan = buildLikeSearchPlan("content", query);
    if (plan.terms.length === 0) {
      return [];
    }
    const where = [...plan.where, ...this.timelinePredicate("summaries.summary_id")];
    const args = [...plan.args];
    if (summaryId !== void 0) {
      where.push(`summary_id IN (${SUMMARY_SOURCE_IDS_SQL})`);
      args.push(summaryId);
    }
    if (conversationId != null) {
      where.push("conversation_id = ?");
      args.push(conversationId);
    }
    if (since) {
      where.push("julianday(created_at) >= julianday(?)");
      args.push(since.toISOString());
    }
    if (before) {
      where.push("julianday(created_at) < julianday(?)");
      args.push(before.toISOString());
    }
    args.push(limit);
    const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const rows = this.db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, content, token_count, file_ids,
                earliest_at, latest_at, descendant_count, descendant_token_count,
                source_message_token_count, has_event_time, created_at
         FROM summaries
         ${whereClause}
         ORDER BY created_at DESC
         LIMIT ?`
    ).all(...args);
    return rows.map((row) => ({
      summaryId: row.summary_id,
      conversationId: row.conversation_id,
      kind: row.kind,
      snippet: createFallbackSnippet(row.content, plan.terms),
      createdAt: parseSqliteDate(row.created_at),
      rank: 0
    }));
  }
  searchRegex(pattern, limit, conversationId, since, before, summaryId) {
    const re = validateRegex(pattern);
    const where = [...this.timelinePredicate("summaries.summary_id")];
    const args = [];
    if (summaryId !== void 0) {
      where.push(`summary_id IN (${SUMMARY_SOURCE_IDS_SQL})`);
      args.push(summaryId);
    }
    if (conversationId != null) {
      where.push("conversation_id = ?");
      args.push(conversationId);
    }
    if (since) {
      where.push("julianday(created_at) >= julianday(?)");
      args.push(since.toISOString());
    }
    if (before) {
      where.push("julianday(created_at) < julianday(?)");
      args.push(before.toISOString());
    }
    const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
    const rows = this.db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, content, token_count, file_ids,
                earliest_at, latest_at, descendant_count, descendant_token_count,
                source_message_token_count, has_event_time, created_at
         FROM summaries
         ${whereClause}
         ORDER BY created_at DESC`
    ).all(...args);
    const results = [];
    for (const row of rows) {
      if (results.length >= limit) {
        break;
      }
      const match = re.exec(row.content);
      if (match) {
        results.push({
          summaryId: row.summary_id,
          conversationId: row.conversation_id,
          kind: row.kind,
          snippet: match[0],
          createdAt: parseSqliteDate(row.created_at),
          rank: 0
        });
      }
    }
    return results;
  }
  // ── Large files ───────────────────────────────────────────────────────────
  async getLargeFile(fileId) {
    const row = this.db.prepare(
      `SELECT file_id, conversation_id, file_name, mime_type, byte_size, storage_uri, exploration_summary, created_at
       FROM large_files WHERE file_id = ?`
    ).get(fileId);
    return row ? toLargeFileRecord(row) : null;
  }
};

// ../_research/lcm-full-20261021/src/promotion/passive-tags.ts
function passiveTypeTag(category) {
  switch (category) {
    case "decision":
      return "type:preference";
    case "error":
      return "type:gotcha";
    case "plan":
      return "type:decision";
    case "role":
    case "context":
      return "type:user-context";
    case "env":
      return "type:environment";
    case "git":
    case "intent":
    case "task":
    case "security":
      return "type:workflow";
    default:
      return "type:pattern";
  }
}

// ../_research/lcm-full-20261021/src/db/votes.ts
function decodeLegacyTags(value) {
  let tags = value;
  if (typeof tags === "string") {
    const text = tags;
    try {
      const decoded = JSON.parse(text);
      tags = Array.isArray(decoded) ? decoded : [text];
    } catch {
      tags = [text];
    }
  }
  return Array.isArray(tags) && tags.every((tag) => typeof tag === "string") ? tags : null;
}

// ../_research/lcm-full-20261021/src/db/migration.ts
import { randomUUID as randomUUID2 } from "node:crypto";
import { homedir } from "node:os";
import { join as join5 } from "node:path";

// ../_research/lcm-full-20261021/src/db/features.ts
var featureCache = /* @__PURE__ */ new WeakMap();
function probeFts5(db) {
  try {
    db.exec("DROP TABLE IF EXISTS temp.__lcm_fts5_probe");
    db.exec("CREATE VIRTUAL TABLE temp.__lcm_fts5_probe USING fts5(content)");
    db.exec("DROP TABLE temp.__lcm_fts5_probe");
    return true;
  } catch {
    try {
      db.exec("DROP TABLE IF EXISTS temp.__lcm_fts5_probe");
    } catch {
    }
    return false;
  }
}
function getLcmDbFeatures(db) {
  const cached = featureCache.get(db);
  if (cached) {
    return cached;
  }
  const detected = {
    fts5Available: probeFts5(db)
  };
  featureCache.set(db, detected);
  return detected;
}

// ../_research/lcm-full-20261021/src/db/transcript-cursor.ts
function ensureTranscriptCursorTable(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS codex_ingest_cursors (
    conversation_id INTEGER PRIMARY KEY REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    transcript_path TEXT NOT NULL,
    byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
    message_count INTEGER NOT NULL CHECK (message_count >= 0),
    file_device TEXT NOT NULL,
    file_inode TEXT NOT NULL,
    record_boundary INTEGER NOT NULL CHECK (record_boundary IN (0, 1)),
    prefix_fingerprint TEXT
  )`);
  const columns = db.prepare("PRAGMA table_info(codex_ingest_cursors)").all();
  if (!columns.some((column) => column.name === "prefix_fingerprint")) {
    db.exec("ALTER TABLE codex_ingest_cursors ADD COLUMN prefix_fingerprint TEXT");
  }
  for (const [name, type2] of [["claude_redaction_key", "TEXT"], ["claude_database_identity", "TEXT"], ["claude_last_message_id", "INTEGER"], ["claude_validated_count", "INTEGER"], ["claude_pending_fingerprint", "TEXT"]]) {
    if (!columns.some((column) => column.name === name)) db.exec(`ALTER TABLE codex_ingest_cursors ADD COLUMN ${name} ${type2}`);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS claude_tool_use_models (
    conversation_id INTEGER NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    tool_use_id TEXT NOT NULL,
    model TEXT NOT NULL,
    PRIMARY KEY (conversation_id, tool_use_id)
  )`);
  const invalidate = (ids) => `UPDATE codex_ingest_cursors SET prefix_fingerprint = NULL
    WHERE claude_redaction_key IS NOT NULL AND conversation_id IN (
      SELECT conversation_id FROM conversations WHERE session_id IN (${ids})
    );`;
  const messageSession = (row) => `SELECT session_id FROM conversations WHERE conversation_id = ${row}.conversation_id`;
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS claude_cursor_message_update AFTER UPDATE OF conversation_id, seq, role, content ON messages
    WHEN OLD.conversation_id IS NOT NEW.conversation_id OR OLD.seq IS NOT NEW.seq OR OLD.role IS NOT NEW.role OR OLD.content IS NOT NEW.content
    BEGIN ${invalidate(`${messageSession("OLD")} UNION ${messageSession("NEW")}`)} END;
    CREATE TRIGGER IF NOT EXISTS claude_cursor_message_delete BEFORE DELETE ON messages
    BEGIN ${invalidate(messageSession("OLD"))} END;
    CREATE TRIGGER IF NOT EXISTS claude_cursor_conversation_update AFTER UPDATE OF session_id, created_at, role_tagging, parser_shape ON conversations
    BEGIN ${invalidate("SELECT OLD.session_id UNION SELECT NEW.session_id")} END;
    CREATE TRIGGER IF NOT EXISTS claude_cursor_conversation_delete BEFORE DELETE ON conversations
    BEGIN ${invalidate("SELECT OLD.session_id")} END;
    CREATE TRIGGER IF NOT EXISTS claude_cursor_conversation_insert AFTER INSERT ON conversations
    BEGIN ${invalidate("SELECT NEW.session_id")} END;
  `);
  for (const operation of ["INSERT", "UPDATE", "DELETE"]) {
    const rows = operation === "INSERT" ? ["NEW"] : operation === "DELETE" ? ["OLD"] : ["OLD", "NEW"];
    db.exec(`CREATE TRIGGER IF NOT EXISTS claude_cursor_part_${operation.toLowerCase()} AFTER ${operation} ON message_parts
      BEGIN ${rows.map((row) => `UPDATE codex_ingest_cursors SET prefix_fingerprint = NULL
        WHERE claude_redaction_key IS NOT NULL AND ${row}.part_type = 'compaction'
        AND ${row}.message_id <= claude_last_message_id AND conversation_id IN (
          SELECT c.conversation_id FROM conversations c JOIN conversations changed ON changed.session_id = c.session_id
          JOIN messages m ON m.conversation_id = changed.conversation_id WHERE m.message_id = ${row}.message_id
        );`).join("\n")} END;`);
  }
}

// ../_research/lcm-full-20261021/src/db/tool-lesson-schema.ts
var INCREMENTAL_TABLES = `
    CREATE TABLE IF NOT EXISTS tool_lesson_changes (
      session_id TEXT NOT NULL, call_id TEXT NOT NULL, PRIMARY KEY(session_id, call_id)
    );
    CREATE TABLE IF NOT EXISTS tool_lesson_invalid_sessions (session_id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS tool_lesson_contributions (
      call_row INTEGER NOT NULL, kind TEXT NOT NULL, lesson_key TEXT NOT NULL,
      session_id TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
      call_order TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(call_row, kind)
    );
    CREATE INDEX IF NOT EXISTS tool_lesson_contributions_session_idx ON tool_lesson_contributions(session_id, call_row, kind);
    CREATE INDEX IF NOT EXISTS tool_lesson_contributions_first_idx ON tool_lesson_contributions(lesson_key, first_seen);
    CREATE INDEX IF NOT EXISTS tool_lesson_contributions_last_idx ON tool_lesson_contributions(lesson_key, last_seen);
    CREATE INDEX IF NOT EXISTS tool_lesson_contributions_order_idx ON tool_lesson_contributions(lesson_key, call_order);
    CREATE TABLE IF NOT EXISTS tool_lesson_successes (
      call_row INTEGER PRIMARY KEY, session_id TEXT NOT NULL, shape TEXT NOT NULL,
      call_order TEXT NOT NULL, seen TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS tool_lesson_successes_shape_idx ON tool_lesson_successes(shape, call_order);
    CREATE INDEX IF NOT EXISTS tool_lesson_successes_session_idx ON tool_lesson_successes(session_id, call_row);
    CREATE TABLE IF NOT EXISTS tool_lesson_totals (
      lesson_key TEXT PRIMARY KEY, data TEXT NOT NULL, dirty INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS tool_lesson_totals_dirty_idx ON tool_lesson_totals(dirty, lesson_key);
    CREATE TABLE IF NOT EXISTS tool_lesson_progress (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1), pair_count INTEGER NOT NULL,
      pending INTEGER NOT NULL DEFAULT 0
    );
    INSERT OR IGNORE INTO tool_lesson_progress (singleton, pair_count) VALUES (1, 0);
    CREATE INDEX IF NOT EXISTS tool_lessons_key_generation_idx ON tool_lessons(lesson_key, generation);
    CREATE INDEX IF NOT EXISTS tool_lessons_active_order_idx ON tool_lessons(retired, last_seen DESC, lesson_key);
`;
var SOURCE_TRIGGERS = `
    CREATE TRIGGER IF NOT EXISTS tool_lesson_call_insert AFTER INSERT ON transcript_tool_calls BEGIN
      INSERT INTO tool_lesson_changes VALUES (NEW.session_id, NEW.call_id) ON CONFLICT DO NOTHING;
    END;
    CREATE TRIGGER IF NOT EXISTS tool_lesson_call_update AFTER UPDATE ON transcript_tool_calls
    WHEN OLD.input IS NOT NEW.input OR OLD.name IS NOT NEW.name OR OLD.outcome IS NOT NEW.outcome
      OR OLD.block_reason IS NOT NEW.block_reason OR OLD.truncated IS NOT NEW.truncated
      OR OLD.message_id IS NOT NEW.message_id OR OLD.session_id IS NOT NEW.session_id OR OLD.call_id IS NOT NEW.call_id
    BEGIN
      INSERT INTO tool_lesson_changes VALUES (NEW.session_id, NEW.call_id) ON CONFLICT DO NOTHING;
      INSERT INTO tool_lesson_invalid_sessions
        SELECT OLD.session_id WHERE OLD.message_id IS NOT NEW.message_id
          OR OLD.session_id IS NOT NEW.session_id OR OLD.call_id IS NOT NEW.call_id ON CONFLICT DO NOTHING;
    END;
    CREATE TRIGGER IF NOT EXISTS tool_lesson_call_delete AFTER DELETE ON transcript_tool_calls BEGIN
      INSERT INTO tool_lesson_invalid_sessions VALUES (OLD.session_id) ON CONFLICT DO NOTHING;
      DELETE FROM tool_lesson_changes WHERE session_id = OLD.session_id AND call_id = OLD.call_id;
    END;
    CREATE TRIGGER IF NOT EXISTS tool_lesson_message_time AFTER UPDATE OF event_at, created_at ON messages
    WHEN OLD.event_at IS NOT NEW.event_at OR OLD.created_at IS NOT NEW.created_at BEGIN
      INSERT INTO tool_lesson_changes
        SELECT session_id, call_id FROM transcript_tool_calls WHERE message_id = NEW.message_id ON CONFLICT DO NOTHING;
    END;
    CREATE TRIGGER IF NOT EXISTS tool_lesson_worker_insert AFTER INSERT ON summarize_workers BEGIN
      INSERT INTO tool_lesson_invalid_sessions VALUES (NEW.session_id) ON CONFLICT DO NOTHING;
    END;
    CREATE TRIGGER IF NOT EXISTS tool_lesson_worker_delete AFTER DELETE ON summarize_workers BEGIN
      INSERT INTO tool_lesson_invalid_sessions VALUES (OLD.session_id) ON CONFLICT DO NOTHING;
    END;
`;
function ensureToolLessonIncrementalSchema(db) {
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'tool_lesson_changes'").get()) {
    rederiveToolLessonShapesOnce(db);
    return;
  }
  db.exec("SAVEPOINT tool_lesson_schema");
  try {
    db.exec(INCREMENTAL_TABLES);
    db.exec(SOURCE_TRIGGERS);
    db.exec(`
      DELETE FROM tool_lessons WHERE generation IS NOT (SELECT generation FROM tool_lesson_state WHERE singleton = 1);
      INSERT INTO tool_lesson_changes SELECT session_id, call_id FROM transcript_tool_calls;
      INSERT INTO tool_lesson_totals (lesson_key, data)
        SELECT lesson_key, json_set(data, '$.count', 0, '$.sessionCounts', json('{}'))
        FROM tool_lessons WHERE generation = (SELECT generation FROM tool_lesson_state WHERE singleton = 1);
    `);
    db.exec("RELEASE tool_lesson_schema");
  } catch (error) {
    db.exec("ROLLBACK TO tool_lesson_schema; RELEASE tool_lesson_schema");
    throw error;
  }
  rederiveToolLessonShapesOnce(db);
}
function rederiveToolLessonShapesOnce(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS tool_lesson_shape_backfill (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    completed_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  if (db.prepare("SELECT 1 FROM tool_lesson_shape_backfill WHERE id = 1").get()) return;
  db.exec("BEGIN IMMEDIATE");
  try {
    if (!db.prepare("SELECT 1 FROM tool_lesson_shape_backfill WHERE id = 1").get()) {
      db.exec(`INSERT OR IGNORE INTO tool_lesson_changes SELECT session_id, call_id FROM transcript_tool_calls;
        INSERT INTO tool_lesson_shape_backfill (id) VALUES (1);`);
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

// ../_research/lcm-full-20261021/src/db/recall-usage.ts
function usageRows(source) {
  const tags = `CASE WHEN json_valid(p.tags) THEN
    CASE WHEN json_type(p.tags) = 'array' THEN p.tags ELSE '[]' END ELSE '[]' END`;
  return `INSERT INTO recall_usage (signal_id, memory_id)
    SELECT p.id, substr(t.value, 11) FROM ${source} AS p, json_each(${tags}) AS t
    WHERE p.archived_at IS NULL AND p.tags LIKE '%"signal:memory_used"%'
      AND t.type = 'text' AND substr(t.value, 1, 10) = 'memory_id:' AND length(t.value) > 10
      AND instr(p.tags, '"memory_id:' || substr(t.value, 11) || '"') > 0
      AND NOT EXISTS (SELECT 1 FROM json_each(${tags}) WHERE type != 'text')
      AND (SELECT COUNT(*) FROM json_each(${tags}) WHERE substr(value, 1, 10) = 'memory_id:') = 1;`;
}
function installRecallUsage(db) {
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'recall_usage'").get()) return;
  db.exec("BEGIN IMMEDIATE");
  try {
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'recall_usage'").get()) {
      db.exec(`CREATE TABLE recall_usage (
        signal_id TEXT PRIMARY KEY,
        memory_id TEXT NOT NULL
      );
      CREATE INDEX recall_usage_memory_idx ON recall_usage (memory_id);
      CREATE TRIGGER recall_usage_insert AFTER INSERT ON promoted BEGIN
        ${usageRows("(SELECT NEW.id AS id, NEW.tags AS tags, NEW.archived_at AS archived_at)")}
      END;
      CREATE TRIGGER recall_usage_update AFTER UPDATE OF id, tags, archived_at ON promoted BEGIN
        DELETE FROM recall_usage WHERE signal_id = OLD.id;
        ${usageRows("(SELECT NEW.id AS id, NEW.tags AS tags, NEW.archived_at AS archived_at)")}
      END;
      CREATE TRIGGER recall_usage_delete AFTER DELETE ON promoted BEGIN
        DELETE FROM recall_usage WHERE signal_id = OLD.id;
      END;
      ${usageRows("promoted")}`);
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

// ../_research/lcm-full-20261021/src/subagent-attribution.ts
import { existsSync as existsSync3, lstatSync, readdirSync as readdirSync2, readFileSync as readFileSync3 } from "node:fs";
import { basename as basename2, join as join4 } from "node:path";
var EMPTY_ATTRIBUTION = {
  parentSessionId: null,
  subagentType: null,
  subagentDesc: null
};
function readSubagentAttribution(transcriptPath, folderSessionId) {
  const metaPath = transcriptPath.replace(/\.jsonl$/, ".meta.json");
  if (!existsSync3(metaPath)) return EMPTY_ATTRIBUTION;
  let parsed;
  try {
    parsed = JSON.parse(readFileSync3(metaPath, "utf-8"));
  } catch {
    return EMPTY_ATTRIBUTION;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return EMPTY_ATTRIBUTION;
  const meta = parsed;
  const parentAgentId = typeof meta.parentAgentId === "string" && meta.parentAgentId ? meta.parentAgentId : null;
  return {
    parentSessionId: parentAgentId ? `agent-${parentAgentId}` : folderSessionId,
    subagentType: typeof meta.agentType === "string" ? meta.agentType : null,
    subagentDesc: typeof meta.description === "string" ? meta.description : null
  };
}
function discoverSubagentTranscripts(sessionDir) {
  const subagentsDir = join4(sessionDir, "subagents");
  if (!isRealDirectory(subagentsDir)) return [];
  const walk = { folderSessionId: basename2(sessionDir), out: [], seenSessionIds: /* @__PURE__ */ new Set() };
  walkSubagentDir(subagentsDir, walk);
  return walk.out;
}
function isRealDirectory(path) {
  try {
    return lstatSync(path).isDirectory();
  } catch {
    return false;
  }
}
function listEntries(dir) {
  try {
    return readdirSync2(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}
function walkSubagentDir(dir, walk) {
  for (const entry of listEntries(dir)) {
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      walkSubagentDir(join4(dir, entry.name), walk);
      continue;
    }
    const found = isSubagentTranscriptFile(entry) ? discoveredTranscript(join4(dir, entry.name), walk.folderSessionId) : null;
    if (!found) continue;
    if (walk.seenSessionIds.has(found.sessionId)) {
      console.error(`subagent-attribution: duplicate sessionId "${found.sessionId}" at ${found.path}, keeping the first`);
      continue;
    }
    walk.seenSessionIds.add(found.sessionId);
    walk.out.push(found);
  }
}
function isSubagentTranscriptFile(entry) {
  return entry.isFile() && entry.name !== "journal.jsonl" && entry.name.endsWith(".jsonl");
}
function discoveredTranscript(path, folderSessionId) {
  try {
    const st = lstatSync(path);
    if (st.isSymbolicLink()) return null;
    return {
      path,
      sessionId: basename2(path, ".jsonl"),
      mtime: st.mtimeMs,
      attribution: readSubagentAttribution(path, folderSessionId)
    };
  } catch {
    return null;
  }
}
function walkSubagentTranscripts(claudeProjectsDir) {
  const entries = [];
  if (!existsSync3(claudeProjectsDir)) return entries;
  for (const projectEntry of readdirSync2(claudeProjectsDir, { withFileTypes: true })) {
    if (!projectEntry.isDirectory()) continue;
    collectProjectSubagentTranscripts(join4(claudeProjectsDir, projectEntry.name), entries);
  }
  return entries;
}
function collectProjectSubagentTranscripts(projectDir, out) {
  for (const sessionEntry of readdirSync2(projectDir, { withFileTypes: true })) {
    if (!sessionEntry.isDirectory()) continue;
    out.push(...discoverSubagentTranscripts(join4(projectDir, sessionEntry.name)));
  }
}

// ../_research/lcm-full-20261021/src/db/migration.ts
function defaultClaudeProjectsDir() {
  return join5(homedir(), ".claude", "projects");
}
function withForeignKeysDisabled(db, fn) {
  db.exec("PRAGMA foreign_keys = OFF");
  try {
    fn();
  } finally {
    db.exec("PRAGMA foreign_keys = ON");
  }
}
function ensureReplayLedgerOutcomeColumn(db) {
  const columns = db.prepare(`PRAGMA table_info(replay_ledger)`).all();
  if (!columns.some((col) => col.name === "outcome")) {
    db.exec(`ALTER TABLE replay_ledger ADD COLUMN outcome TEXT NOT NULL DEFAULT 'compacted'`);
  }
}
var LLM_USAGE_ADDED_COLUMNS = [
  ["tokens_input_total", "INTEGER NOT NULL DEFAULT 0"],
  ["tokens_cached_total", "INTEGER NOT NULL DEFAULT 0"],
  ["tokens_output_total", "INTEGER NOT NULL DEFAULT 0"],
  ["cost_usd_total", "REAL"],
  ["calls_with_cost", "INTEGER NOT NULL DEFAULT 0"],
  ["calls_estimated", "INTEGER NOT NULL DEFAULT 0"]
];
function ensureLlmUsageBreakdownColumns(db) {
  const columns = db.prepare(`PRAGMA table_info(llm_usage_stats)`).all();
  for (const [name, ddl] of LLM_USAGE_ADDED_COLUMNS) {
    if (!columns.some((col) => col.name === name)) {
      db.exec(`ALTER TABLE llm_usage_stats ADD COLUMN ${name} ${ddl}`);
    }
  }
}
function ensureSummaryDepthColumn(db) {
  const summaryColumns = db.prepare(`PRAGMA table_info(summaries)`).all();
  const hasDepth = summaryColumns.some((col) => col.name === "depth");
  if (!hasDepth) {
    db.exec(`ALTER TABLE summaries ADD COLUMN depth INTEGER NOT NULL DEFAULT 0`);
  }
  return !hasDepth;
}
function ensureSummaryMetadataColumns(db) {
  const summaryColumns = db.prepare(`PRAGMA table_info(summaries)`).all();
  const hasEarliestAt = summaryColumns.some((col) => col.name === "earliest_at");
  const hasLatestAt = summaryColumns.some((col) => col.name === "latest_at");
  const hasDescendantCount = summaryColumns.some((col) => col.name === "descendant_count");
  const hasDescendantTokenCount = summaryColumns.some((col) => col.name === "descendant_token_count");
  const hasSourceMessageTokenCount = summaryColumns.some(
    (col) => col.name === "source_message_token_count"
  );
  if (!hasEarliestAt) {
    db.exec(`ALTER TABLE summaries ADD COLUMN earliest_at TEXT`);
  }
  if (!hasLatestAt) {
    db.exec(`ALTER TABLE summaries ADD COLUMN latest_at TEXT`);
  }
  if (!hasDescendantCount) {
    db.exec(`ALTER TABLE summaries ADD COLUMN descendant_count INTEGER NOT NULL DEFAULT 0`);
  }
  if (!hasDescendantTokenCount) {
    db.exec(`ALTER TABLE summaries ADD COLUMN descendant_token_count INTEGER NOT NULL DEFAULT 0`);
  }
  if (!hasSourceMessageTokenCount) {
    db.exec(`ALTER TABLE summaries ADD COLUMN source_message_token_count INTEGER NOT NULL DEFAULT 0`);
  }
  return !hasEarliestAt || !hasLatestAt || !hasDescendantCount || !hasDescendantTokenCount || !hasSourceMessageTokenCount;
}
function ensureSummaryEventTimeFlag(db) {
  const summaryColumns = db.prepare(`PRAGMA table_info(summaries)`).all();
  if (!summaryColumns.some((col) => col.name === "has_event_time")) {
    db.exec("ALTER TABLE summaries ADD COLUMN has_event_time INTEGER NOT NULL DEFAULT 0");
  }
}
function ensureSubagentAttributionColumns(db) {
  const columns = db.prepare(`PRAGMA table_info(conversations)`).all();
  const wanted = ["parent_session_id", "subagent_type", "subagent_desc"];
  for (const name of wanted) {
    if (!columns.some((col) => col.name === name)) {
      db.exec(`ALTER TABLE conversations ADD COLUMN ${name} TEXT DEFAULT NULL`);
    }
  }
}
function ensureConversationBoundaryColumn(db) {
  const columns = db.prepare(`PRAGMA table_info(conversations)`).all();
  if (!columns.some((col) => col.name === "opened_by_entry_id")) {
    db.exec(`ALTER TABLE conversations ADD COLUMN opened_by_entry_id TEXT DEFAULT NULL`);
  }
}
function ensureSubagentBackfillTable(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS subagent_attribution_backfill (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      unmatched_count INTEGER NOT NULL DEFAULT 0,
      completed_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}
function hasUnresolvedAgentConversations(db) {
  const row = db.prepare(`SELECT 1 FROM conversations WHERE session_id LIKE 'agent-%' AND parent_session_id IS NULL LIMIT 1`).get();
  return row !== void 0;
}
function applySubagentAttributionBackfill(db, claudeProjectsDir) {
  const bySessionId = new Map(walkSubagentTranscripts(claudeProjectsDir).map((e) => [e.sessionId, e.attribution]));
  const rows = db.prepare(`SELECT conversation_id, session_id FROM conversations WHERE session_id LIKE 'agent-%' AND parent_session_id IS NULL`).all();
  const updateStmt = db.prepare(
    `UPDATE conversations SET parent_session_id = ?, subagent_type = ?, subagent_desc = ? WHERE conversation_id = ?`
  );
  let unmatched = 0;
  for (const row of rows) {
    const attribution = bySessionId.get(row.session_id);
    if (!attribution) {
      unmatched++;
      continue;
    }
    updateStmt.run(attribution.parentSessionId, attribution.subagentType, attribution.subagentDesc, row.conversation_id);
  }
  return unmatched;
}
function backfillSubagentAttribution(db, claudeProjectsDir) {
  ensureSubagentBackfillTable(db);
  if (db.prepare(`SELECT 1 FROM subagent_attribution_backfill WHERE id = 1`).get()) return;
  const unmatched = hasUnresolvedAgentConversations(db) ? applySubagentAttributionBackfill(db, claudeProjectsDir) : 0;
  db.prepare(`INSERT INTO subagent_attribution_backfill (id, unmatched_count) VALUES (1, ?)`).run(unmatched);
}
function parseTimestamp(value) {
  if (typeof value !== "string" || !value.trim()) {
    return null;
  }
  const direct = new Date(value);
  if (!Number.isNaN(direct.getTime())) {
    return direct;
  }
  const normalized = value.includes("T") ? value : `${value.replace(" ", "T")}Z`;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}
function isoStringOrNull(value) {
  return value ? value.toISOString() : null;
}
function backfillSummaryDepths(db) {
  db.exec(`UPDATE summaries SET depth = 0 WHERE kind = 'leaf'`);
  const conversationRows = db.prepare(`SELECT DISTINCT conversation_id FROM summaries WHERE kind = 'condensed'`).all();
  if (conversationRows.length === 0) {
    return;
  }
  const updateDepthStmt = db.prepare(`UPDATE summaries SET depth = ? WHERE summary_id = ?`);
  for (const row of conversationRows) {
    const conversationId = row.conversation_id;
    const summaries = db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, token_count, created_at
         FROM summaries
         WHERE conversation_id = ?`
    ).all(conversationId);
    const depthBySummaryId = /* @__PURE__ */ new Map();
    const unresolvedCondensedIds = /* @__PURE__ */ new Set();
    for (const summary of summaries) {
      if (summary.kind === "leaf") {
        depthBySummaryId.set(summary.summary_id, 0);
        continue;
      }
      unresolvedCondensedIds.add(summary.summary_id);
    }
    const edges = db.prepare(
      `SELECT summary_id, parent_summary_id
         FROM summary_parents
         WHERE summary_id IN (
           SELECT summary_id FROM summaries
           WHERE conversation_id = ? AND kind = 'condensed'
         )`
    ).all(conversationId);
    const parentsBySummaryId = /* @__PURE__ */ new Map();
    for (const edge of edges) {
      const existing = parentsBySummaryId.get(edge.summary_id) ?? [];
      existing.push(edge.parent_summary_id);
      parentsBySummaryId.set(edge.summary_id, existing);
    }
    while (unresolvedCondensedIds.size > 0) {
      let progressed = false;
      for (const summaryId of [...unresolvedCondensedIds]) {
        const parentIds = parentsBySummaryId.get(summaryId) ?? [];
        if (parentIds.length === 0) {
          depthBySummaryId.set(summaryId, 1);
          unresolvedCondensedIds.delete(summaryId);
          progressed = true;
          continue;
        }
        let maxParentDepth = -1;
        let allParentsResolved = true;
        for (const parentId of parentIds) {
          const parentDepth = depthBySummaryId.get(parentId);
          if (parentDepth == null) {
            allParentsResolved = false;
            break;
          }
          if (parentDepth > maxParentDepth) {
            maxParentDepth = parentDepth;
          }
        }
        if (!allParentsResolved) {
          continue;
        }
        depthBySummaryId.set(summaryId, maxParentDepth + 1);
        unresolvedCondensedIds.delete(summaryId);
        progressed = true;
      }
      if (!progressed) {
        for (const summaryId of unresolvedCondensedIds) {
          depthBySummaryId.set(summaryId, 1);
        }
        unresolvedCondensedIds.clear();
      }
    }
    for (const summary of summaries) {
      const depth = depthBySummaryId.get(summary.summary_id);
      if (depth == null) {
        continue;
      }
      updateDepthStmt.run(depth, summary.summary_id);
    }
  }
}
function backfillSummaryMetadata(db) {
  const conversationRows = db.prepare(`SELECT DISTINCT conversation_id FROM summaries`).all();
  if (conversationRows.length === 0) {
    return;
  }
  const updateMetadataStmt = db.prepare(
    `UPDATE summaries
     SET earliest_at = ?, latest_at = ?, has_event_time = ?, descendant_count = ?,
         descendant_token_count = ?, source_message_token_count = ?
     WHERE summary_id = ?`
  );
  for (const conversationRow of conversationRows) {
    const conversationId = conversationRow.conversation_id;
    const summaries = db.prepare(
      `SELECT summary_id, conversation_id, kind, depth, token_count, created_at
         FROM summaries
         WHERE conversation_id = ?
         ORDER BY depth ASC, created_at ASC`
    ).all(conversationId);
    if (summaries.length === 0) {
      continue;
    }
    const leafRanges = db.prepare(
      `SELECT
           sm.summary_id,
           COUNT(m.event_at) AS known_event_count,
           strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(MIN(julianday(m.event_at)), MIN(julianday(m.created_at)))) AS earliest_at,
           strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(MAX(julianday(m.event_at)), MAX(julianday(m.created_at)))) AS latest_at,
           COALESCE(SUM(m.token_count), 0) AS source_message_token_count
         FROM summary_messages sm
         JOIN messages m ON m.message_id = sm.message_id
         JOIN summaries s ON s.summary_id = sm.summary_id
         WHERE s.conversation_id = ? AND s.kind = 'leaf'
         GROUP BY sm.summary_id`
    ).all(conversationId);
    const leafRangeBySummaryId = new Map(
      leafRanges.map((row) => [
        row.summary_id,
        {
          hasEventTime: row.known_event_count > 0,
          earliestAt: row.earliest_at,
          latestAt: row.latest_at,
          sourceMessageTokenCount: row.source_message_token_count
        }
      ])
    );
    const edges = db.prepare(
      `SELECT summary_id, parent_summary_id
         FROM summary_parents
         WHERE summary_id IN (
           SELECT summary_id FROM summaries WHERE conversation_id = ?
         )`
    ).all(conversationId);
    const parentsBySummaryId = /* @__PURE__ */ new Map();
    for (const edge of edges) {
      const existing = parentsBySummaryId.get(edge.summary_id) ?? [];
      existing.push(edge.parent_summary_id);
      parentsBySummaryId.set(edge.summary_id, existing);
    }
    const metadataBySummaryId = /* @__PURE__ */ new Map();
    const tokenCountBySummaryId = new Map(
      summaries.map((summary) => [summary.summary_id, Math.max(0, Math.floor(summary.token_count ?? 0))])
    );
    for (const summary of summaries) {
      const fallbackDate = parseTimestamp(summary.created_at);
      if (summary.kind === "leaf") {
        const range = leafRangeBySummaryId.get(summary.summary_id);
        const earliestAt2 = parseTimestamp(range?.earliestAt ?? summary.created_at) ?? fallbackDate;
        const latestAt2 = parseTimestamp(range?.latestAt ?? summary.created_at) ?? fallbackDate;
        metadataBySummaryId.set(summary.summary_id, {
          hasEventTime: range?.hasEventTime ?? false,
          earliestAt: earliestAt2,
          latestAt: latestAt2,
          descendantCount: 0,
          descendantTokenCount: 0,
          sourceMessageTokenCount: Math.max(
            0,
            Math.floor(range?.sourceMessageTokenCount ?? 0)
          )
        });
        continue;
      }
      const parentIds = parentsBySummaryId.get(summary.summary_id) ?? [];
      if (parentIds.length === 0) {
        metadataBySummaryId.set(summary.summary_id, {
          hasEventTime: false,
          earliestAt: fallbackDate,
          latestAt: fallbackDate,
          descendantCount: 0,
          descendantTokenCount: 0,
          sourceMessageTokenCount: 0
        });
        continue;
      }
      let earliestAt = null;
      let latestAt = null;
      let descendantCount = 0;
      let descendantTokenCount = 0;
      let sourceMessageTokenCount = 0;
      const hasEventTime = parentIds.some((id) => metadataBySummaryId.get(id)?.hasEventTime);
      for (const parentId of parentIds) {
        const parentMetadata = metadataBySummaryId.get(parentId);
        if (!parentMetadata) {
          continue;
        }
        const parentEarliest = parentMetadata.earliestAt;
        if ((parentMetadata.hasEventTime || !hasEventTime) && parentEarliest && (!earliestAt || parentEarliest < earliestAt)) {
          earliestAt = parentEarliest;
        }
        const parentLatest = parentMetadata.latestAt;
        if ((parentMetadata.hasEventTime || !hasEventTime) && parentLatest && (!latestAt || parentLatest > latestAt)) {
          latestAt = parentLatest;
        }
        descendantCount += Math.max(0, parentMetadata.descendantCount) + 1;
        const parentTokenCount = tokenCountBySummaryId.get(parentId) ?? 0;
        descendantTokenCount += Math.max(0, parentTokenCount) + Math.max(0, parentMetadata.descendantTokenCount);
        sourceMessageTokenCount += Math.max(0, parentMetadata.sourceMessageTokenCount);
      }
      metadataBySummaryId.set(summary.summary_id, {
        hasEventTime,
        earliestAt: earliestAt ?? fallbackDate,
        latestAt: latestAt ?? fallbackDate,
        descendantCount: Math.max(0, descendantCount),
        descendantTokenCount: Math.max(0, descendantTokenCount),
        sourceMessageTokenCount: Math.max(0, sourceMessageTokenCount)
      });
    }
    for (const summary of summaries) {
      const metadata = metadataBySummaryId.get(summary.summary_id);
      if (!metadata) {
        continue;
      }
      updateMetadataStmt.run(
        isoStringOrNull(metadata.earliestAt),
        isoStringOrNull(metadata.latestAt),
        Number(metadata.hasEventTime),
        Math.max(0, metadata.descendantCount),
        Math.max(0, metadata.descendantTokenCount),
        Math.max(0, metadata.sourceMessageTokenCount),
        summary.summary_id
      );
    }
  }
}
function backfillSummaryFieldsOnce(db, columnsAdded) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS summary_backfill (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      completed_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  if (!columnsAdded && db.prepare(`SELECT 1 FROM summary_backfill WHERE id = 1`).get()) return;
  backfillSummaryDepths(db);
  backfillSummaryMetadata(db);
  db.prepare(`INSERT OR REPLACE INTO summary_backfill (id) VALUES (1)`).run();
}
function ensureMessagePartsSkillCommandTypes(db) {
  const existing = db.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='message_parts'`).get();
  if (!existing?.sql || existing.sql.includes("'skill'")) return;
  const columns = db.prepare(`PRAGMA table_info(message_parts)`).all().map((c) => c.name).join(", ");
  db.exec("SAVEPOINT message_parts_rebuild");
  try {
    db.exec(`
      CREATE TABLE message_parts_new (
        part_id TEXT PRIMARY KEY,
        message_id INTEGER NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
        session_id TEXT NOT NULL,
        part_type TEXT NOT NULL CHECK (part_type IN (
          'text', 'reasoning', 'tool', 'patch', 'file',
          'subtask', 'compaction', 'step_start', 'step_finish',
          'snapshot', 'agent', 'retry', 'skill', 'command'
        )),
        ordinal INTEGER NOT NULL,
        text_content TEXT,
        is_ignored INTEGER,
        is_synthetic INTEGER,
        tool_call_id TEXT,
        tool_name TEXT,
        tool_status TEXT,
        tool_input TEXT,
        tool_output TEXT,
        tool_error TEXT,
        tool_title TEXT,
        patch_hash TEXT,
        patch_files TEXT,
        file_mime TEXT,
        file_name TEXT,
        file_url TEXT,
        subtask_prompt TEXT,
        subtask_desc TEXT,
        subtask_agent TEXT,
        step_reason TEXT,
        step_cost REAL,
        step_tokens_in INTEGER,
        step_tokens_out INTEGER,
        snapshot_hash TEXT,
        compaction_auto INTEGER,
        metadata TEXT,
        UNIQUE (message_id, ordinal)
      );
    `);
    db.exec(`INSERT INTO message_parts_new (${columns}) SELECT ${columns} FROM message_parts;`);
    db.exec("DROP TABLE message_parts;");
    db.exec("ALTER TABLE message_parts_new RENAME TO message_parts;");
    db.exec(`
      CREATE INDEX IF NOT EXISTS message_parts_message_idx ON message_parts (message_id);
      CREATE INDEX IF NOT EXISTS message_parts_type_idx ON message_parts (part_type);
    `);
    db.exec("RELEASE SAVEPOINT message_parts_rebuild");
  } catch (err) {
    db.exec("ROLLBACK TO SAVEPOINT message_parts_rebuild");
    db.exec("RELEASE SAVEPOINT message_parts_rebuild");
    throw err;
  }
}
function ensureMessagePartsBackfillTable(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS message_parts_skill_command_backfill (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      unmatched_skill_count INTEGER NOT NULL DEFAULT 0,
      completed_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}
function insertMessagePart(db, input) {
  db.prepare(
    `INSERT INTO message_parts (part_id, message_id, session_id, part_type, ordinal, tool_name, tool_input)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(randomUUID2(), input.messageId, input.sessionId, input.part.type, input.ordinal, input.part.name, input.part.args);
}
function backfillCommandParts(db) {
  const rows = db.prepare(
    `SELECT m.message_id, m.content, c.session_id
       FROM messages m JOIN conversations c ON c.conversation_id = m.conversation_id
       WHERE m.content LIKE '%<command-name>%'`
  ).all();
  for (const row of rows) {
    extractCommandParts(row.content).forEach(
      (part, ordinal) => insertMessagePart(db, { messageId: row.message_id, sessionId: row.session_id, ordinal, part })
    );
  }
}
var LAUNCHING_SKILL_PREFIX = "Launching skill: ";
function backfillSkillParts(db) {
  const rows = db.prepare(
    `SELECT m.message_id, m.content, c.session_id
       FROM messages m JOIN conversations c ON c.conversation_id = m.conversation_id
       WHERE m.content LIKE ?`
  ).all(`${LAUNCHING_SKILL_PREFIX}%`);
  let unmatched = 0;
  for (const row of rows) {
    const name = row.content.slice(LAUNCHING_SKILL_PREFIX.length).split("\n")[0].trim();
    if (!name) {
      unmatched++;
      continue;
    }
    insertMessagePart(db, {
      messageId: row.message_id,
      sessionId: row.session_id,
      ordinal: 0,
      part: { type: "skill", name, args: null }
    });
  }
  return unmatched;
}
function backfillMessagePartsSkillCommand(db) {
  ensureMessagePartsBackfillTable(db);
  if (db.prepare(`SELECT 1 FROM message_parts_skill_command_backfill WHERE id = 1`).get()) return;
  backfillCommandParts(db);
  const unmatchedSkillCount = backfillSkillParts(db);
  db.prepare(`INSERT INTO message_parts_skill_command_backfill (id, unmatched_skill_count) VALUES (1, ?)`).run(unmatchedSkillCount);
}
function legacyPromotedTags(stored) {
  try {
    return decodeLegacyTags(JSON.parse(stored));
  } catch {
    return null;
  }
}
function backfillPromotedTagsOnce(db, fts5Available) {
  db.exec(`CREATE TABLE IF NOT EXISTS promoted_tags_backfill (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    completed_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  if (db.prepare("SELECT 1 FROM promoted_tags_backfill WHERE id = 1").get()) return;
  db.exec("BEGIN IMMEDIATE");
  try {
    if (db.prepare("SELECT 1 FROM promoted_tags_backfill WHERE id = 1").get()) {
      db.exec("COMMIT");
      return;
    }
    const update = db.prepare("UPDATE promoted SET tags = ? WHERE rowid = ?");
    const removeFts = fts5Available ? db.prepare("DELETE FROM promoted_fts WHERE rowid = ?") : null;
    const insertFts = fts5Available ? db.prepare("INSERT INTO promoted_fts(rowid, content, tags) VALUES (?, ?, ?)") : null;
    for (const row of db.prepare("SELECT rowid, content, tags, archived_at FROM promoted").iterate()) {
      const { rowid, content, tags: stored, archived_at } = row;
      let tags = legacyPromotedTags(stored);
      if (!tags) continue;
      if (tags.includes("source:passive-capture")) {
        const category = tags.find((tag) => tag.startsWith("category:"))?.slice("category:".length) ?? "";
        tags = tags.filter((tag) => !tag.startsWith("category:"));
        if (!tags.some((tag) => tag.startsWith("type:"))) tags.push(passiveTypeTag(category));
      }
      const normalized = JSON.stringify(tags);
      if (normalized === stored) continue;
      update.run(normalized, rowid);
      removeFts?.run(rowid);
      if (archived_at === null) insertFts?.run(rowid, content, normalized);
    }
    db.prepare("INSERT INTO promoted_tags_backfill (id) VALUES (1)").run();
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}
function removePassiveIntentLabelsOnce(db, fts5Available) {
  db.exec(`CREATE TABLE IF NOT EXISTS passive_intent_repair (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    completed_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  if (db.prepare("SELECT 1 FROM passive_intent_repair WHERE id = 1").get()) return;
  db.exec("BEGIN IMMEDIATE");
  try {
    if (db.prepare("SELECT 1 FROM passive_intent_repair WHERE id = 1").get()) {
      db.exec("COMMIT");
      return;
    }
    const remove = db.prepare("DELETE FROM promoted WHERE rowid = ?");
    const removeFts = fts5Available ? db.prepare("DELETE FROM promoted_fts WHERE rowid = ?") : null;
    for (const row of db.prepare(`SELECT rowid, tags FROM promoted
      WHERE content IN ('implement', 'investigate', 'review', 'refactor')
        AND session_id IS NOT 'manual'`).iterate()) {
      const { rowid, tags } = row;
      if (!legacyPromotedTags(tags)?.includes("source:passive-capture")) continue;
      removeFts?.run(rowid);
      remove.run(rowid);
    }
    db.prepare("INSERT INTO passive_intent_repair (id) VALUES (1)").run();
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}
function runLcmMigrations(db, options) {
  withForeignKeysDisabled(db, () => runLcmMigrationsInner(db, options));
}
function runLcmMigrationsInner(db, options) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS conversations (
      conversation_id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      title TEXT,
      bootstrapped_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS messages (
      message_id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
      seq INTEGER NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant', 'tool')),
      content TEXT NOT NULL,
      token_count INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE (conversation_id, seq)
    );

    CREATE TABLE IF NOT EXISTS summaries (
      summary_id TEXT PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK (kind IN ('leaf', 'condensed')),
      depth INTEGER NOT NULL DEFAULT 0,
      content TEXT NOT NULL,
      token_count INTEGER NOT NULL,
      earliest_at TEXT,
      latest_at TEXT,
      descendant_count INTEGER NOT NULL DEFAULT 0,
      descendant_token_count INTEGER NOT NULL DEFAULT 0,
      source_message_token_count INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      file_ids TEXT NOT NULL DEFAULT '[]'
    );

    CREATE TABLE IF NOT EXISTS message_parts (
      part_id TEXT PRIMARY KEY,
      message_id INTEGER NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
      session_id TEXT NOT NULL,
      part_type TEXT NOT NULL CHECK (part_type IN (
        'text', 'reasoning', 'tool', 'patch', 'file',
        'subtask', 'compaction', 'step_start', 'step_finish',
        'snapshot', 'agent', 'retry', 'skill', 'command'
      )),
      ordinal INTEGER NOT NULL,
      text_content TEXT,
      is_ignored INTEGER,
      is_synthetic INTEGER,
      tool_call_id TEXT,
      tool_name TEXT,
      tool_status TEXT,
      tool_input TEXT,
      tool_output TEXT,
      tool_error TEXT,
      tool_title TEXT,
      patch_hash TEXT,
      patch_files TEXT,
      file_mime TEXT,
      file_name TEXT,
      file_url TEXT,
      subtask_prompt TEXT,
      subtask_desc TEXT,
      subtask_agent TEXT,
      step_reason TEXT,
      step_cost REAL,
      step_tokens_in INTEGER,
      step_tokens_out INTEGER,
      snapshot_hash TEXT,
      compaction_auto INTEGER,
      metadata TEXT,
      UNIQUE (message_id, ordinal)
    );

    CREATE TABLE IF NOT EXISTS summary_messages (
      summary_id TEXT NOT NULL REFERENCES summaries(summary_id) ON DELETE CASCADE,
      message_id INTEGER NOT NULL REFERENCES messages(message_id) ON DELETE RESTRICT,
      ordinal INTEGER NOT NULL,
      PRIMARY KEY (summary_id, message_id)
    );

    CREATE TABLE IF NOT EXISTS summary_parents (
      summary_id TEXT NOT NULL REFERENCES summaries(summary_id) ON DELETE CASCADE,
      parent_summary_id TEXT NOT NULL REFERENCES summaries(summary_id) ON DELETE RESTRICT,
      ordinal INTEGER NOT NULL,
      PRIMARY KEY (summary_id, parent_summary_id)
    );

    CREATE TABLE IF NOT EXISTS context_items (
      conversation_id INTEGER NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
      ordinal INTEGER NOT NULL,
      item_type TEXT NOT NULL CHECK (item_type IN ('message', 'summary')),
      message_id INTEGER REFERENCES messages(message_id) ON DELETE RESTRICT,
      summary_id TEXT REFERENCES summaries(summary_id) ON DELETE RESTRICT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (conversation_id, ordinal),
      CHECK (
        (item_type = 'message' AND message_id IS NOT NULL AND summary_id IS NULL) OR
        (item_type = 'summary' AND summary_id IS NOT NULL AND message_id IS NULL)
      )
    );

    CREATE TABLE IF NOT EXISTS large_files (
      file_id TEXT PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
      file_name TEXT,
      mime_type TEXT,
      byte_size INTEGER,
      storage_uri TEXT NOT NULL,
      exploration_summary TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS conversations_session_idx ON conversations (session_id);
    CREATE INDEX IF NOT EXISTS messages_conv_seq_idx ON messages (conversation_id, seq);
    CREATE INDEX IF NOT EXISTS summaries_conv_created_idx ON summaries (conversation_id, created_at);
    CREATE INDEX IF NOT EXISTS message_parts_message_idx ON message_parts (message_id);
    CREATE INDEX IF NOT EXISTS message_parts_type_idx ON message_parts (part_type);
    CREATE INDEX IF NOT EXISTS summary_messages_message_idx ON summary_messages (message_id);
    CREATE INDEX IF NOT EXISTS summary_parents_parent_idx ON summary_parents (parent_summary_id);
    CREATE INDEX IF NOT EXISTS context_items_conv_idx ON context_items (conversation_id, ordinal);
    CREATE INDEX IF NOT EXISTS context_items_message_idx ON context_items (message_id);
    CREATE INDEX IF NOT EXISTS context_items_summary_idx ON context_items (summary_id);
    CREATE INDEX IF NOT EXISTS large_files_conv_idx ON large_files (conversation_id, created_at);
  `);
  const conversationColumns = db.prepare(`PRAGMA table_info(conversations)`).all();
  const hasBootstrappedAt = conversationColumns.some((col) => col.name === "bootstrapped_at");
  if (!hasBootstrappedAt) {
    db.exec(`ALTER TABLE conversations ADD COLUMN bootstrapped_at TEXT`);
  }
  const messageColumns = db.prepare("PRAGMA table_info(messages)").all();
  if (!messageColumns.some((column) => column.name === "event_at")) db.exec("ALTER TABLE messages ADD COLUMN event_at TEXT");
  if (!messageColumns.some((column) => column.name === "event_time_source")) {
    db.exec("ALTER TABLE messages ADD COLUMN event_time_source TEXT");
  }
  db.exec(`CREATE TABLE IF NOT EXISTS transcript_tool_calls (
    session_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    message_id INTEGER NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    input TEXT,
    input_bytes INTEGER,
    truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN (0, 1)),
    outcome TEXT NOT NULL DEFAULT 'unknown' CHECK(outcome IN ('succeeded', 'failed', 'blocked', 'denied', 'interrupted', 'unknown')),
    harness_error INTEGER CHECK(harness_error IN (0, 1)),
    exit_code INTEGER,
    PRIMARY KEY(session_id, call_id)
  );
  CREATE INDEX IF NOT EXISTS transcript_tool_calls_message_idx ON transcript_tool_calls(message_id);`);
  const callColumns = db.prepare("PRAGMA table_info(transcript_tool_calls)").all();
  if (!callColumns.some((column) => column.name === "block_reason")) db.exec("ALTER TABLE transcript_tool_calls ADD COLUMN block_reason TEXT");
  db.exec(`CREATE INDEX IF NOT EXISTS transcript_tool_calls_session_message_idx ON transcript_tool_calls(session_id, message_id);
    CREATE TABLE IF NOT EXISTS tool_lesson_state (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1), generation INTEGER NOT NULL, calls_seen TEXT
    );
    CREATE TABLE IF NOT EXISTS tool_lessons (
      generation INTEGER NOT NULL, lesson_key TEXT NOT NULL,
      kind TEXT NOT NULL, retired INTEGER NOT NULL DEFAULT 0,
      last_seen TEXT NOT NULL, data TEXT NOT NULL,
      PRIMARY KEY(generation, lesson_key)
    );
    CREATE INDEX IF NOT EXISTS tool_lessons_recent_idx ON tool_lessons(generation, retired, last_seen DESC, lesson_key);`);
  db.exec(`CREATE TABLE IF NOT EXISTS session_web_urls (
    session_id TEXT NOT NULL, url TEXT NOT NULL, PRIMARY KEY(session_id, url)
  );
  CREATE TABLE IF NOT EXISTS session_commits (
    session_id TEXT NOT NULL, message_id INTEGER NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    hash TEXT NOT NULL, subject TEXT, author_at TEXT, committed_at TEXT, branch TEXT, resolved INTEGER NOT NULL CHECK(resolved IN (0, 1)),
    evidence TEXT NOT NULL CHECK(evidence IN ('commit-output', 'session-trailer')), evidence_value TEXT NOT NULL,
    PRIMARY KEY(message_id, evidence, evidence_value, hash)
  );
  CREATE INDEX IF NOT EXISTS session_commits_session_idx ON session_commits(session_id);`);
  const commitColumns = db.prepare("PRAGMA table_info(session_commits)").all();
  if (!commitColumns.some((column) => column.name === "committed_at")) db.exec("ALTER TABLE session_commits ADD COLUMN committed_at TEXT");
  const depthAdded = ensureSummaryDepthColumn(db);
  db.exec("CREATE INDEX IF NOT EXISTS summaries_conv_depth_id_idx ON summaries (conversation_id, depth, summary_id)");
  const metadataAdded = ensureSummaryMetadataColumns(db);
  ensureSummaryEventTimeFlag(db);
  backfillSummaryFieldsOnce(db, depthAdded || metadataAdded);
  ensureMessagePartsSkillCommandTypes(db);
  const redactionStatsRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='redaction_stats'").get();
  const needsRedactionStatsMigration = !redactionStatsRow || redactionStatsRow.sql !== void 0 && !redactionStatsRow.sql.includes("'gitleaks'");
  if (needsRedactionStatsMigration) {
    db.exec(`
      DROP TABLE IF EXISTS redaction_stats;
      CREATE TABLE redaction_stats (
        project_id TEXT NOT NULL,
        category TEXT NOT NULL CHECK(category IN ('built_in', 'global', 'project', 'gitleaks')),
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (project_id, category)
      );
    `);
  }
  db.exec(`
    CREATE TABLE IF NOT EXISTS session_instructions (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      content TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS session_compactions (
      session_id TEXT PRIMARY KEY,
      compacted_at INTEGER NOT NULL
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS promoted (
      id TEXT PRIMARY KEY,
      content TEXT NOT NULL,
      tags TEXT NOT NULL DEFAULT '[]',
      source_summary_id TEXT,
      project_id TEXT NOT NULL,
      session_id TEXT,
      depth INTEGER NOT NULL DEFAULT 0,
      confidence REAL NOT NULL DEFAULT 1.0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS promoted_project_idx ON promoted (project_id, created_at);
  `);
  const taggingColumns = db.prepare(`PRAGMA table_info(conversations)`).all();
  if (!taggingColumns.some((col) => col.name === "role_tagging")) {
    db.exec(`ALTER TABLE conversations ADD COLUMN role_tagging TEXT DEFAULT NULL`);
  }
  if (!taggingColumns.some((col) => col.name === "parser_shape")) {
    db.exec(`ALTER TABLE conversations ADD COLUMN parser_shape TEXT DEFAULT NULL`);
  }
  ensureSubagentAttributionColumns(db);
  ensureConversationBoundaryColumn(db);
  backfillSubagentAttribution(db, options?.claudeProjectsDir ?? defaultClaudeProjectsDir());
  backfillMessagePartsSkillCommand(db);
  const promotedColumns = db.prepare(`PRAGMA table_info(promoted)`).all();
  const hasArchivedAt = promotedColumns.some((col) => col.name === "archived_at");
  if (!hasArchivedAt) {
    db.exec(`ALTER TABLE promoted ADD COLUMN archived_at TEXT DEFAULT NULL`);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS worker_claim_markers (
    session_id TEXT NOT NULL, call_id TEXT NOT NULL, PRIMARY KEY(session_id, call_id)
  );`);
  db.exec(`CREATE TABLE IF NOT EXISTS worker_issued_jobs (
    job_id TEXT PRIMARY KEY, issued_at TEXT NOT NULL DEFAULT (datetime('now'))
  );`);
  db.exec(`CREATE TABLE IF NOT EXISTS summarize_workers (
    session_id TEXT PRIMARY KEY, cwd TEXT NOT NULL, client TEXT NOT NULL,
    owner TEXT, state TEXT NOT NULL CHECK(state IN ('active', 'finished', 'abandoned')),
    exclusion_reason TEXT,
    last_activity TEXT NOT NULL DEFAULT (datetime('now'))
  );`);
  const workerColumns = db.prepare("PRAGMA table_info(summarize_workers)").all();
  ensureToolLessonIncrementalSchema(db);
  if (!workerColumns.some((column) => column.name === "exclusion_reason")) {
    db.exec("ALTER TABLE summarize_workers ADD COLUMN exclusion_reason TEXT");
  }
  db.exec(`
    CREATE TABLE IF NOT EXISTS session_ingest_log (
      session_id TEXT PRIMARY KEY,
      completed_at TEXT NOT NULL DEFAULT (datetime('now')),
      message_count INTEGER NOT NULL DEFAULT 0
    );
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS llm_usage_stats (
      provider TEXT NOT NULL,
      model TEXT NOT NULL,
      calls_total INTEGER NOT NULL DEFAULT 0,
      calls_ok INTEGER NOT NULL DEFAULT 0,
      calls_failed INTEGER NOT NULL DEFAULT 0,
      tokens_spent_total INTEGER NOT NULL DEFAULT 0,
      tokens_input_total INTEGER NOT NULL DEFAULT 0,
      tokens_cached_total INTEGER NOT NULL DEFAULT 0,
      tokens_output_total INTEGER NOT NULL DEFAULT 0,
      -- NULL means no call was ever priced; never read a missing cost as zero.
      cost_usd_total REAL,
      calls_with_cost INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (provider, model)
    );
  `);
  ensureLlmUsageBreakdownColumns(db);
  db.exec(`
    CREATE TABLE IF NOT EXISTS recall_surfacing (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      memory_id TEXT NOT NULL,
      session_id TEXT,
      surfaced_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS recall_surfacing_memory_idx ON recall_surfacing (memory_id);
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS replay_manifest (
      run_id TEXT NOT NULL,
      command TEXT NOT NULL,
      position INTEGER NOT NULL,
      session_id TEXT NOT NULL,
      model TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (run_id, position)
    );
    CREATE INDEX IF NOT EXISTS replay_manifest_session_idx ON replay_manifest (run_id, session_id);
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS replay_ledger (
      run_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      position INTEGER NOT NULL,
      prev_session_id TEXT,
      content_fingerprint TEXT NOT NULL,
      summary_id TEXT,
      model TEXT,
      outcome TEXT NOT NULL DEFAULT 'compacted',
      completed_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (run_id, session_id)
    );
    CREATE INDEX IF NOT EXISTS replay_ledger_position_idx ON replay_ledger (run_id, position);
  `);
  ensureReplayLedgerOutcomeColumn(db);
  ensureTranscriptCursorTable(db);
  installProjectTimeline(db);
  const fts5Available = options?.fts5Available ?? getLcmDbFeatures(db).fts5Available;
  if (!fts5Available) {
    backfillPromotedTagsOnce(db, false);
    removePassiveIntentLabelsOnce(db, false);
    installRecallUsage(db);
    return;
  }
  const hasPromotedFts = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='promoted_fts'").get();
  if (!hasPromotedFts) {
    db.exec(`
      CREATE VIRTUAL TABLE promoted_fts USING fts5(
        content,
        tags,
        tokenize='porter unicode61'
      );
      INSERT INTO promoted_fts(rowid, content, tags)
      SELECT rowid, content, tags FROM promoted WHERE archived_at IS NULL;
    `);
  }
  backfillPromotedTagsOnce(db, true);
  removePassiveIntentLabelsOnce(db, true);
  const hasFts = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='messages_fts'").get();
  if (hasFts) {
    const ftsSchema = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='messages_fts'").get()?.sql;
    if (ftsSchema && ftsSchema.includes("content_rowid")) {
      db.exec("DROP TABLE messages_fts");
      db.exec(`
        CREATE VIRTUAL TABLE messages_fts USING fts5(
          content,
          tokenize='porter unicode61'
        );
        INSERT INTO messages_fts(rowid, content) SELECT message_id, content FROM messages;
      `);
    }
  } else {
    db.exec(`
      CREATE VIRTUAL TABLE messages_fts USING fts5(
        content,
        tokenize='porter unicode61'
      );
    `);
  }
  const summariesFtsInfo = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='summaries_fts'").get();
  const summariesFtsSql = summariesFtsInfo?.sql ?? "";
  const summariesFtsColumns = db.prepare(`PRAGMA table_info(summaries_fts)`).all();
  const hasSummaryIdColumn = summariesFtsColumns.some((col) => col.name === "summary_id");
  const shouldRecreateSummariesFts = !summariesFtsInfo || !hasSummaryIdColumn || summariesFtsSql.includes("content_rowid='summary_id'") || summariesFtsSql.includes('content_rowid="summary_id"');
  if (shouldRecreateSummariesFts) {
    db.exec(`
      DROP TABLE IF EXISTS summaries_fts;
      CREATE VIRTUAL TABLE summaries_fts USING fts5(
        summary_id UNINDEXED,
        content,
        tokenize='porter unicode61'
      );
      INSERT INTO summaries_fts(summary_id, content)
      SELECT summary_id, content FROM summaries;
    `);
  }
  installRecallUsage(db);
}
export {
  ConversationStore,
  SummaryStore,
  runLcmMigrations
};
/*! Bundled license information:

js-yaml/dist/js-yaml.mjs:
  (*! js-yaml 4.1.1 https://github.com/nodeca/js-yaml @license MIT *)
*/
