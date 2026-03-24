# restore-symbol

* Update: `20260324`

Forked from [HeiTanBc/restore-symbol](https://github.com/HeiTanBc/restore-symbol), do many furture optimization, to facilicate restore symbols for iOS Mach-O file

## Effect Compare

* Before restore symbol
  * ![before_restore_symbol](assets/img/before_restore_symbol.jpg)
* After restore symbol
  * for: `restore-symbol`=`rs`'s ObjC + block
    * ![after_restore_symbol_whatsapp_rs](assets/img/after_restore_symbol_whatsapp_rs.jpg)
  * for: `IDA`'s Functions + Names + block
    * ![after_restored_symbol_whatsapp_ida](assets/img/after_restored_symbol_whatsapp_ida.jpg)

## Prepare

* get `restore-symbol` executable file
  * download from release
  * or download code then build by yourself
* then makesure workable
  * show version
    * `./restore-symbol --version`
  * show help
    * `./restore-symbol --help` == `./restore-symbol`

### Download from release

download from [releases](https://github.com/crifan/restore-symbol/releases/) (then rename to `restore-symbol`)

### Compile by yourself

* download code
  ```bash
  git clone --recursive https://github.com/crifan/restore-symbol.git
  ```
* compile to generate `restore-symbol`
  ```bash
  cd restore-symbol
  make
  ```

## Usage

* Summary
  * for anyone: have `IDA Pro`
    * (1) `ida_search_block.py`: scan and writeback **block** symbols to IDA
    * (2) [`idaExportSymbol.py`](https://github.com/crifan/idaExportSymbol): export **IDA** (`Functions` (include ObjC) + `Names` + `block`) symbols to json file
    * (3) `restore-symbol`: **restore** all symbols for iOS Mach-O binary file
  * for anyone: no `IDA Pro`
    * `restore-symol` : restore (only) **ObjC** symbols
* Details:

### (1) scan and writeback **block** symbols to IDA

* (1) scan and writeback **block** symbols to IDA
  * run `tools/IDAScripts/search_oc_block/ida_search_block.py` in IDA
    * default config: 
      * `enableWriteback = True`: write back (scanned objc block symbol name) into IDA
      * `isExportToFile = True`: meanwhile also export block symbol file (for furture use, or manual check)
  * Example
    * WhatsApp
      * ![ida_writeback_block_symbol_whatsapp](assets/img/ida_writeback_block_symbol_whatsapp.jpg)

### (2) export **IDA** symbols (`Functions` + `Names`, and above **block** symbols) to json file

* (2) export **IDA** symbols (`Functions`(inside include ObjC symbols) + `Names`, and above **block** symbols) to json file
  * run [`idaExportSymbol.py`](https://github.com/crifan/idaExportSymbol) in IDA
    * for details, refer to: [crifan/idaExportSymbol](https://github.com/crifan/idaExportSymbol)
  * Attention
    * makesure `IDA's image base` == `Mach-O vmaddr base` is same
      * Example
        * WhatsApp
          * before: IDA image base=`0x100C00000`
            * ![ida_before_rebase_0x100C00000](assets/img/ida_before_rebase_0x100C00000.jpg)
          * after `Rebase program`, IDA's image base=`0x100000000`
            * ![ida_after_rebase_0x100000000](assets/img/ida_after_rebase_0x100000000.jpg)
          * same with (MachOView see) WhatsApp's vmaddr=`0x100000000`
            * ![machoview_whatsapp_text_vmaddr_0x100000000](assets/img/machoview_whatsapp_text_vmaddr_0x100000000.jpg)

### (3) **restore** all symbols for iOS Mach-O binary file

* (3) **restore** all symbols for iOS Mach-O binary file
  * run `./restore-symbol` to restore IDA exported all symbols (IDA's Functions+Names and block)
    ```bash
    restore-symbol -w true -s false -j {exported_IDA_symbols.json} -o {outputFile_RestoredSymbol} {inputMachOFile}
    ```
    * Note
      * `-w true` == Overwrite output file if existed
      * `-s false` == **Not** Scan objc symbols, for previous step `ida_search_block.py`'s `enableWriteback = True` already scan and write back the objc symbols into mach-o binary == mach-o binary alread contains objc symbols
      * `-j {exported_IDA_symbols.json}` == json file, which contain all (objc + renamed functions) symbols
      * `-o {outputFile_RestoredSymbol}` == output file
      * `{inputMachOFile}` == input mach-o file
  * Example
    * WhatsApp
      ```bash
      ./restore-symbol -w true -s false -j WhatsApp_IDASymbols_FunctionsNames_20231129_223621.json -o test/WhatsApp/output/WhatsApp_mergedSymbols_20231129 test/WhatsApp/input/WhatsApp
      ```
        * ![restore_symbol_whatsapp](assets/img/restore_symbol_whatsapp.jpg)

### `restore-symol` (only) ObjC symbols

use `restore-symol` to restore **ObjC** symbols, passing argument with `-s true`=`--scan-objc-symbols true`

```bash
restore-symbol -s true -o {outputFile_RestoredSymbol} {inputMachOFile}
```

* Note
  * after `restore-symbol` restored ObjC symbol, there are some wrong symbol
    * how to fix: use above ([`idaExportSymbol.py`](https://github.com/crifan/idaExportSymbol) exported) **IDA** symbols

## More Usage Case

* Exmaple
  * WhatsApp
    * Only export ObjC symbols to json file + not remove duplicated ObjC symbol
      ```bash
      restore-symbol test/WhatsApp/input/WhatsApp -s true -r false -m false -b test/WhatsApp/output/ObjcSymbols/WhatsApp_objcSymbolsDuplicated_20231201.json
      ```
    * Only export ObjC symbols to json file + remove duplicated ObjC symbol
      ```bash
      restore-symbol test/WhatsApp/input/WhatsApp -s true -r false -m true -b test/WhatsApp/output/ObjcSymbols/WhatsApp_objcSymbolsDuplicated_20231201.json
      ```
    * scan and restore ObjC symbol, use default remove duplicated ObjC symbol
      ```bash
      restore-symbol test/WhatsApp/input/WhatsApp -s true -r true -m true -o test/WhatsApp/output/WhatsApp_restoredObjcSymbols_20231404
      ```
    * scan and restore ObjC symbol, use default remove duplicated ObjC symbol + overwrite output file if exsited
      ```bash
      restore-symbol test/WhatsApp/input/WhatsApp -s true -r true -m true -o test/WhatsApp/output/WhatsApp_restoredObjcSymbols_20231404 -w true
      ```
    * restore from imported json symbol file
      ```bash
      restore-symbol test/WhatsApp/input/WhatsApp -s false -r true -j WhatsApp_IDASymbols_FunctionsNames_20231130_104313.json -o test/WhatsApp/output/WhatsApp_restoredIdaAllSymbols_20231404
      ```

## Post step

after export IDA symbol, if you want automate whole process of repack ipa, you can use:

[crifan/AutoRepackIpa: Auto repack ipa](https://github.com/crifan/AutoRepackIpa)

## Changelog

* 20231115
  * other updates for `mergeSymbols.py`
  * `exportIDASymbol.py` moved to separate repo: [crifan/idaExportSymbol](https://github.com/crifan/idaExportSymbol)
* 20231103
  * add `exportIDASymbol.py` (now at [crifan/idaExportSymbol](https://github.com/crifan/idaExportSymbol))
    * to export IDA symbols
  * add `tools/mergeSymbols/mergeSymbols.py`
    * to merge all symbols from restore-symbol restored, exported from IDA functions list, scanned from IDA block
* 20231027
  * `search_oc_block/ida_search_block.py`
    * Converted to support [IDA 7.4+](https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml) (`SegName`->`get_segm_name`, `Qword`->`get_qword`, etc.)
    * Converted to Python 3.x(`print xxx`->`print(xxx)`, `filter`->`list` etc.)
    * Fixed bug: `RecursionError: maximum recursion depth exceeded while calling a Python object`

## restore-symbol help

```bash
➜  restore-symbol git:(master) ✗ ./restore-symbol --help

restore-symbol 2.0 (64 bit)

Usage: restore-symbol [-o <output-file>] [-j <json-symbol-file>] [-w <true/false>] [-s <true/false>] [-b <objcSymbolsOutputFile>] [-r <true/false>] [-p] <input-mach-O-file>

  where options are:
    -h,--help                                              Print this help info then exit
    -v,--version                                           Print version info then exit
    -o,--output <output-file>                              New mach-O file path
                                                             default: null
    -j,--json <json-symbol-file>                           Json file containing extra symbol info, the key is "name","address"
                                                             like this:
                                                               [
                                                                 {
                                                                   "name": "main",
                                                                   "address": "0xXXXXXX"
                                                                 },
                                                                 {
                                                                   "name": "-[XXXX XXXXX]",
                                                                   "address": "0xXXXXXX"
                                                                 },
                                                                 ...
                                                               ]
                                                             default: null
    -w,--overwrite-output-file <true/false>                Overwrite output file if existed
                                                             default: false
    -s,--scan-objc-symbols <true/false>                    Scan objc symbols or not
                                                             default: true
    -m,--remove-duplicated-objc-symbols <true/false>       Remove duplicated objc symbols or not after scan objc symbols
                                                             default: true
    -b,--objc-symbols-output-file <objcSymbolsOutputFile>  Export objc symbols to file
                                                             default: null
    -r,--restore-symols <true/false>                       Restore symbol or not
                                                             default: true
    -p,--replace-restrict                                  New mach-O file will replace the LC_SEGMENT(__RESTRICT,__restrict)
                                                             with LC_SEGMENT(__restrict,__restrict) to close dylib inject protection
                                                             default: disabled
```

## TODO

* [ ] update `class-dump` to support new load command: `0x80000033`, `0x80000034`

------

A reverse engineering tool to restore stripped symbol table for iOS app.

Example: restore symbol for Alipay

![after_restore](assets/img/after_restore.jpg)

## How to use

### Just restore symbol of oc method

- 1. Download source code and compile.

```bash
git clone --recursive https://github.com/HeiTanBc/restore-symbol
cd restore-symbol && make
./restore-symbol
```

- 2. Restore symbol using this command. It will output a new mach-o file with symbol.

```bash
./restore-symbol /pathto/origin_mach_o_file -o /pathto/mach_o_with_symbol 
```

- 3. Copy the new mach-o file (with symbol) to app bundle, replace the origin mach-o file with new mach-o file. Resign app bundle.

```bash
codesign -f -s - --timestamp=none --generate-entitlement-der --entitlement ./xxxx.app.xcent ./xxxx.app
```

- 4. Install the app bundle to iOS device, and use lldb to debug the app. Maybe you can use the ```ios-deploy```, or other way you like. If you use ```ios-deploy``` , you can execute this command.

```bash
brew install ios-deploy
ios-deploy -d -b xxxx.app
```

- 5. Now you can use ```b -[class method]``` to set breakpoint.

### Restore symbol of oc block

- 1. Search block symbol in IDA to get json symbol file, using script([`search_oc_block/ida_search_block.py`](./search_oc_block/ida_search_block.py)) .

![](http://blog.imjun.net/posts/restore-symbol-of-iOS-app/ida_result_position.png)

![](http://blog.imjun.net/posts/restore-symbol-of-iOS-app/ida_result_sample.jpg)

- 2. Use command line tool(restore-symbol) to inject oc method symbols and block symbols into mach o file.

```bash
./restore-symbol /pathto/origin_mach_o_file -o /pathto/mach_o_with_symbol -j /pathto/block_symbol.json
```

- 3. Other steps(resign, install, debug) are samen as above.

## Command Line Usage

```bash
# ./restore-symbol --help

restore-symbol 1.0 (64 bit)

Usage: restore-symbol -o <output-file> [-j <json-symbol-file>] <mach-o-file>

  where options are:
    -o,--output <output-file>                              New mach-o-file path
    -s,--scan-objc-symbols <true/false>                    true/false to enable/disable to disable scan objc symbols
    -e,--export-objc-symbol <output-objc-symbol-file>      Export ObjC symbol file while restore ObjC symbol
    --replace-restrict                                     New mach-o-file will replace the LC_SEGMENT(__RESTRICT,__restrict)
                                                           with LC_SEGMENT(__restrict,__restrict) to close dylib inject protection
    -j,--json <json-symbol-file>                           Json file containing extra symbol info, the key is "name","address"
                                   like this:
                               
                                    [
                                         {
                                          "name": "main", 
                                          "address": "0xXXXXXX"
                                         }, 
                                         {
                                          "name": "-[XXXX XXXXX]", 
                                          "address": "0xXXXXXX"
                                         },
                                         .... 
                                        ]
    -h,--help                      Print this help info then exit
```
