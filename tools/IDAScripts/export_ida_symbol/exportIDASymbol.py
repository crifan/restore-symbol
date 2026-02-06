# Function: IDA script plugin, export (Functions, Names) symbol from IDA (for Mach-O format)
# Author: Crifan Li
# Update: 20260206

# import idc
# import sys
# print("Try debug IDA Python plugin script in VSCode")
# print(sys.executable)
# idcHere = idc.here()
# print("idcHere=%s" % idcHere)
# idcHereHex = hex(idcHere)
# print("idcHereHex=%s" % idcHereHex)

import idautils
import idc
import idaapi
# from idaapi import PluginForm
import ida_loader
import ida_nalt
import ida_segment
import operator
import csv
import sys
import json
import re
import os
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
import time
import codecs

################################################################################
# Config & Settings
################################################################################

isVerbose = False
# isVerbose = True
print("isVerbose=%s" % isVerbose)

isExportToFile = True
# isExportToFile = False
print("isExportToFile=%s" % isExportToFile)

# enable demangle name or not
enableDemangleName = True
# enableDemangleName = False
print("enableDemangleName=%s" % enableDemangleName)

if isExportToFile:
  outputFolder = None
  # outputFolder = "/Users/crifan/dev/dev_root/crifan/github/restore-symbol/tools/IDAScripts/export_ida_symbol/output"
  print("outputFolder=%s" % outputFolder)

################################################################################
# Document
################################################################################

# IDA Python API:
#   https://www.hex-rays.com/products/ida/support/idapython_docs/index.html
#
#   idc
#     https://hex-rays.com//products/ida/support/idapython_docs/idc.html

################################################################################
# Util Function
################################################################################

def logMain(mainStr):
  mainDelimiter = "="*40
  print("%s %s %s" % (mainDelimiter, mainStr, mainDelimiter))

def logSub(subStr):
  subDelimiter = "-"*30
  print("%s %s %s" % (subDelimiter, subStr, subDelimiter))

def datetimeToStr(inputDatetime, format="%Y%m%d_%H%M%S"):
    """Convert datetime to string

    Args:
        inputDatetime (datetime): datetime value
    Returns:
        str
    Raises:
    Examples:
        datetime.datetime(2020, 4, 21, 15, 44, 13, 2000) -> '20200421_154413'
    """
    datetimeStr = inputDatetime.strftime(format=format)
    # print("inputDatetime=%s -> datetimeStr=%s" % (inputDatetime, datetimeStr)) # 2020-04-21 15:08:59.787623
    return datetimeStr

def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
    """
    get current datetime then format to string

    eg:
        20171111_220722

    :param outputFormat: datetime output format
    :return: current datetime formatted string
    """
    curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
    # curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
    curDatetimeStr = datetimeToStr(curDatetime, format=outputFormat)
    return curDatetimeStr

def saveJsonToFile(fullFilename, jsonValue, indent=2, fileEncoding="utf-8"):
    """
        save json dict into file
        for non-ascii string, output encoded string, without \\u xxxx
    """
    with codecs.open(fullFilename, 'w', encoding=fileEncoding) as jsonFp:
        json.dump(jsonValue, jsonFp, indent=indent, ensure_ascii=False)
        # logging.debug("Complete save json %s", fullFilename)

def isObjcFunctionName(funcName):
  """
  check is ObjC function name or not
  eg:
    "+[WAAvatarStringsActions editAvatar]" -> True
    "-[ParentGroupInfoViewController initWithParentGroupChatSession:userContext:recentlyLinkedGroupJIDs:]" -> True
    "-[OKEvolveSegmentationVC proCard]_116" -> True
    "-[WAAvatarStickerUpSellSupplementaryView .cxx_destruct]" -> True
    "sub_10004C6D8" -> False
    "protocol witness for RawRepresentable.init(rawValue:) in conformance UIFont.FontWeight" -> True
  """
  isMatchObjcFuncName = re.match(r"^[\-\+]\[\w+ [\w\.\:]+\]\w*$", funcName)
  isObjcFuncName = bool(isMatchObjcFuncName)
  # print("funcName=%s -> isObjcFuncName=%s" % (funcName, isObjcFuncName))
  return isObjcFuncName

# testFuncNameList = [
#   "+[WAAvatarStringsActions editAvatar]",
#   "-[ParentGroupInfoViewController initWithParentGroupChatSession:userContext:recentlyLinkedGroupJIDs:]",
#   "-[OKEvolveSegmentationVC proCard]_116",
#   "-[WAAvatarStickerUpSellSupplementaryView .cxx_destruct]",
#   "sub_10004C6D8",
#   "protocol witness for RawRepresentable.init(rawValue:) in conformance UIFont.FontWeight",
# ]

# for eachFuncName in testFuncNameList:
#   isObjcFunctionName(eachFuncName)

#-------------------- IDA Utils --------------------
# Note: more IDA util functions, please refer: 
#   https://github.com/crifan/crifanLibPython/blob/master/python3/crifanLib/thirdParty/crifanIDA.py

def ida_getInfo():
  """
  get IDA info
  """
  info = idaapi.get_inf_structure()
  # print("info=%s" % info)
  return info

def ida_printInfo(info):
  """
  print IDA info
  """
  version = info.version
  print("version=%s" % version)
  is64Bit = info.is_64bit()
  print("is64Bit=%s" % is64Bit)
  procName = info.procname
  print("procName=%s" % procName)
  entryPoint = info.start_ea
  print("entryPoint=0x%X" % entryPoint)
  baseAddr = info.baseaddr
  print("baseAddr=0x%X" % baseAddr)

def ida_printAllImports():
  """
  print all imports lib and functions inside lib"""
  nimps = ida_nalt.get_import_module_qty()
  print("Found %d import(s)..." % nimps)
  for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    if not name:
      print("Failed to get import module name for [%d] %s" % (i, name))
      name = "<unnamed>"
    else:
      print("[%d] %s" % (i, name))

    def imp_cb(ea, name, ordinal):
        if not name:
            print("%08x: ordinal #%d" % (ea, ordinal))
        else:
            print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    ida_nalt.enum_import_names(i, imp_cb)

def ida_printSegment(curSeg):
  """
  print segment info
    Note: in IDA, segment == section
  """
  segName = curSeg.name
  # print("type(segName)=%s" % type(segName))
  segSelector = curSeg.sel
  segStartAddr = curSeg.start_ea
  segEndAddr = curSeg.end_ea
  print("Segment: [0x%X-0x%X] name=%s, selector=%s : seg=%s" % (segStartAddr, segEndAddr, segName, segSelector, curSeg))

def ida_getSegmentList():
  """
  get segment list
  """
  segList = []
  segNum = ida_segment.get_segm_qty()
  for segIdx in range(segNum):
    curSeg = ida_segment.getnseg(segIdx)
    # print("curSeg=%s" % curSeg)
    segList.append(curSeg)
    # ida_printSegment(curSeg)
  return segList

def ida_testGetSegment():
  """
  test get segment info
  """
  # textSeg = ida_segment.get_segm_by_name("__TEXT")
  # dataSeg = ida_segment.get_segm_by_name("__DATA")

  # ida_getSegmentList()

  # NAME___TEXT = "21"
  # NAME___TEXT = 21
  # NAME___TEXT = "__TEXT,__text"
  # NAME___TEXT = "__TEXT:__text"
  # NAME___TEXT = ".text"

  """
    __TEXT,__text
    __TEXT,__stubs
    __TEXT,__stub_helper
    __TEXT,__objc_stubs
    __TEXT,__const
    __TEXT,__objc_methname
    __TEXT,__cstring
    __TEXT,__swift5_typeref
    __TEXT,__swift5_protos
    __TEXT,__swift5_proto
    __TEXT,__swift5_types
    __TEXT,__objc_classname
    __TEXT,__objc_methtype
    __TEXT,__gcc_except_tab
    __TEXT,__ustring
    __TEXT,__unwind_info
    __TEXT,__eh_frame
    __TEXT,__oslogstring

    __DATA,__got
    __DATA,__la_symbol_ptr
    __DATA,__mod_init_func
    __DATA,__const
    __DATA,__cfstring
    __DATA,__objc_classlist
    __DATA,__objc_catlist
    __DATA,__objc_protolist
    __DATA,__objc_imageinfo
    __DATA,__objc_const
    __DATA,__objc_selrefs
    __DATA,__objc_protorefs
    __DATA,__objc_classrefs
    __DATA,__objc_superrefs
    __DATA,__objc_ivar
    __DATA,__objc_data
    __DATA,__data
    __DATA,__objc_stublist
    __DATA,__swift_hooks
    __DATA,__swift51_hooks
    __DATA,__s_async_hook
    __DATA,__swift56_hooks
    __DATA,__thread_vars
    __DATA,__thread_bss
    __DATA,__bss
    __DATA,__common
  """

  # __TEXT,__text
  NAME___text = "__text"
  textSeg = ida_segment.get_segm_by_name(NAME___text)
  print("textSeg: %s -> %s" % (NAME___text, textSeg))
  ida_printSegment(textSeg)

  # __TEXT,__objc_methname
  NAME___objc_methname = "__objc_methname"
  objcMethNameSeg = ida_segment.get_segm_by_name(NAME___objc_methname)
  print("objcMethNameSeg: %s -> %s" % (NAME___objc_methname, objcMethNameSeg))
  ida_printSegment(objcMethNameSeg)

  # __DATA,__got
  NAME___got = "__got"
  gotSeg = ida_segment.get_segm_by_name(NAME___got)
  print("gotSeg: %s -> %s" % (NAME___got, gotSeg))
  ida_printSegment(gotSeg)

  # __DATA,__data
  # NAME___DATA = "22"
  # NAME___DATA = 22
  NAME___DATA = "__data"
  dataSeg = ida_segment.get_segm_by_name(NAME___DATA)
  print("dataSeg: %s -> %s" % (NAME___DATA, dataSeg))
  ida_printSegment(dataSeg)

  # exist two one: __TEXT,__const / __DATA,__const
  NAME___const = "__const"
  constSeg = ida_segment.get_segm_by_name(NAME___const)
  print("constSeg: %s -> %s" % (NAME___const, constSeg))
  ida_printSegment(constSeg)

def ida_getDemangledName(origSymbolName):
  """
  use IDA to get demangled name for original symbol name
  """
  retName = origSymbolName
  # demangledName = idc.demangle_name(origSymbolName, idc.get_inf_attr(idc.INF_SHORT_DN))
  # https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
  demangledName = idc.demangle_name(origSymbolName, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
  if demangledName:
    retName = demangledName

  # do extra post process:
  # remove/replace invalid char for non-objc function name
  isNotObjcFuncName = not isObjcFunctionName(retName)
  # print("isNotObjcFuncName=%s" % isNotObjcFuncName)
  if isNotObjcFuncName:
    retName = retName.replace("?", "")
    retName = retName.replace(" ", "_")
    retName = retName.replace("*", "_")
  # print("origSymbolName=%s -> retName=%s" % (origSymbolName, retName))
  return retName

def ida_getCurrentFolder():
  """
  get current folder for IDA current opened binary file
    Example:
      -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
      -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app/Frameworks/SharedModules.framework
  """
  curFolder = None
  
  # 尝试 1: 获取 IDA 记录的输入文件路径
  inputFileFullPath = ida_nalt.get_input_file_path()
  
  # 检查该路径是否真的存在
  if inputFileFullPath and os.path.exists(inputFileFullPath):
    # 路径存在，且不是 iOS 设备路径 (/var/containers...)
    if not inputFileFullPath.startswith("/var/containers/Bundle/Application"):
      curFolder = os.path.dirname(inputFileFullPath)

  # 尝试 2: 如果上面的路径不存在（文件夹改名了）或者不合法，使用 IDB 文件的路径
  if not curFolder:
    print("Input file path invalid or not found. Fallback to IDB path.")
    idb_full_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    curFolder = os.path.dirname(idb_full_path)

  curFolder = os.path.abspath(curFolder)
  print("Final curFolder=%s" % curFolder)
  # here work:
  # . -> /Users/crifan/dev/dev_root/iosReverse/WhatsApp/ipa/Payload/WhatsApp.app
  return curFolder


################################################################################
# Main
################################################################################

logMain("Prepare")

imageBase = idaapi.get_imagebase()
# imageBaseStr = "ImageBase0x%X" % imageBase
print("Image Base: 0x%X = %d" % (imageBase, imageBase))

idaVersion = idaapi.IDA_SDK_VERSION
print("IDA Version: %s" % idaVersion)

idaRootFilename = ida_nalt.get_root_filename()
print("IDA root filename: %s" % idaRootFilename)

if isExportToFile:
  if not outputFolder:
    outputFolder = ida_getCurrentFolder()
    print("outputFolder=%s" % outputFolder)

# changeLogStr = imageBaseStr
# changeLogStr = "omitImportFunc"
changeLogStr = "FunctionsNames"

# outputFilename = "IDAFunctionsSymbol"
outputFilename = "IDASymbols"
# outputFullFilename = "%s_%s_%s.json" % (getFilenameNoPointSuffix(__file__), outputFilename, getCurDatetimeStr())
# outputFullFilename = "%s_%s_%s.json" % (idaRootFilename, outputFilename, getCurDatetimeStr())
# outputFullFilename = "%s_%s_%s_%s.json" % (idaRootFilename, outputFilename, imageBaseStr, getCurDatetimeStr())
outputFullFilename = "%s_%s_%s_%s.json" % (idaRootFilename, outputFilename, changeLogStr, getCurDatetimeStr())
print("outputFullFilename=%s" % outputFullFilename)

lastDataSegmentSectionName = "__common"
commonSeg = ida_segment.get_segm_by_name(lastDataSegmentSectionName)
print("__common segment: %s -> %s" % (lastDataSegmentSectionName, commonSeg))
ida_printSegment(commonSeg)
lastValidEndAddr = commonSeg.end_ea
print("End valid Functions Symbol address: 0x%X" % lastValidEndAddr)

functionsSymbolDictList = []

logMain("Exporting IDA Symbols")

logSub("Functions Symbols")

# normal code:
functionAddrList = []
functionIterator = idautils.Functions()
# print("type(functionList)=%s" % type(functionList))
for curFuncAddr in functionIterator:
  functionAddrList.append(curFuncAddr)

# # for debug: demangled name
# functionAddrList = [0x1007288A4, 0x10002E9FC, 0x103A9D3F0, 0x1007F5A38, 0x1007AB0C8] # WhatsApp
# # functionAddrList = [0x1007288A4, 0x10002E9FC, 0x1007F5A38, 0x1007AB0C8] # WhatsApp

totalFunctionsCount = len(functionAddrList)
print("totalFunctionsCount=%s" % totalFunctionsCount)

# # for debug
# impFunNum = 0

validFunctionsSymbolCount = 0
invalidFunctionsSymbolCount = 0

eliteLogPerNum = int(totalFunctionsCount / 100)
print("eliteLogPerNum=%s" % eliteLogPerNum)

curNum = 0
for curFunc in functionAddrList:
  curNum += 1
  # print("curFunc=%s" % curFunc)
  # curFuncAddrStr = hex(curFunc)
  curFuncAddrStr = "0x%X" % curFunc
  curFuncName = idc.get_func_name(curFunc)

  # # for debug
  # logSub("[%d] %s" % (curNum, curFuncAddrStr))
  # if not curFuncName:
  #   curFuncName = idc.get_name(curFunc)
  #   print("curFuncName=%s" % curFuncName)

  if enableDemangleName:
    curFuncName = ida_getDemangledName(curFuncName)
  # print("curFunc=0x%X -> curFuncName=%s" % (curFunc, curFuncName))

  # # for debug
  # continue

  curFuncAttr_end = idc.get_func_attr(curFunc, attr=idc.FUNCATTR_END)

  isValid = not (curFuncAttr_end > lastValidEndAddr)

  if isValid:
    validFunctionsSymbolCount += 1

    isLogCurrent = False
    if isVerbose:
       isLogCurrent = True
    else:
      if (curNum % eliteLogPerNum == 0):
       isLogCurrent = True

    curFuncAttr_start = idc.get_func_attr(curFunc, attr=idc.FUNCATTR_START)
    curFuncSize = curFuncAttr_end - curFuncAttr_start
    curFuncSizeStr = "0x%X" % curFuncSize

    curFuncAttr_flags = idc.get_func_flags(curFunc)
    curFuncFlagsStr = "0x%X" % curFuncAttr_flags

    # curFuncComments = idc.get_func_cmt(curFunc, repeatable=0)
    # curFuncAttr_owner = idc.get_func_attr(curFunc, attr=idc.FUNCATTR_OWNER)

    # # for debug
    # if curFuncName.startswith("__imp"):
    #   impFunNum += 1

    # if impFunNum >= 3:
    #   llllll

    # # for debug
    # if 0x1000062F0 == curFunc:
    #   isLogCurrent = True

    if isLogCurrent:
      # print("[%d] addr=%s, name=%s, size=%s, flags=%s, owner=0x%X" % (toPrintNum, curFuncAddrStr, curFuncName, curFuncSizeStr, curFuncFlagsStr, curFuncAttr_owner))
      print("[%d/%d] addr=%s, name=%s, size=%s" % (curNum, totalFunctionsCount, curFuncAddrStr, curFuncName, curFuncSizeStr))
    
    # # for debug
    # if 0x1000062F0 == curFunc:
    #   curDemangledFuncName = idc.demangle_name(curFuncName, get_inf_attr(INF_SHORT_DN))
    #   print("%s -> %s" % (curFuncName, curDemangledFuncName))
    #   llllll

    curSymbolDict = {
      "name": curFuncName,
      "address": curFuncAddrStr,
      "size": curFuncSizeStr,
    }
    functionsSymbolDictList.append(curSymbolDict)
  else:
    invalidFunctionsSymbolCount += 1

validFunctionsSymbolCount = len(functionsSymbolDictList)
print("validFunctionsSymbolCount=%s" % validFunctionsSymbolCount)

logSub("Names Symbols")

# nameTupleList = []
# nameNameList = []
# nameAddrList = []
# nameTupleIterator = idautils.Names()
# for nameTuple in nameTupleIterator:
#   # print("nameTuple=%s" % (nameTuple))
#   nameName, nameAddr = nameTuple
#   nameNameList.append(nameName)
#   nameAddrList.append(nameAddr)
#   nameTupleList.append(nameTuple)
# nameNum = len(nameTupleList)
# print("nameNum=%s" % nameNum)

# # isAllFuncSymInNames = True
# funcNameAndAddrBothInNamesDict = {}
# funcNameNotInNamesList = []
# funcAddrNotInNamesList = []
# funcNameAndAddrBothNotInNamesDict = {}
# for funcSymNum, eachFuncSymDict in enumerate(functionsSymbolDictList, start=1):
#   funcName = eachFuncSymDict["name"]
#   funcAddrStr = eachFuncSymDict["address"]
#   funcAddr = int(funcAddrStr, base=16)
#   isFuncNameInNames = funcName in nameNameList
#   isFuncAddrInNames = funcAddr in nameAddrList
#   curInfoStr = ""
#   if (isFuncNameInNames==False) and (isFuncAddrInNames==False):
#     funcNameAndAddrBothNotInNamesDict[funcName] = funcAddr
#     curInfoStr = "both not in Names: [0x0%X] %s" % (funcAddr, funcName)
#   elif (isFuncNameInNames == False):
#     funcNameNotInNamesList.append(funcName)
#     curInfoStr = "name not in Names: %s" % funcName
#   elif (isFuncAddrInNames == False):
#     funcAddrNotInNamesList.append(funcAddr)
#     curInfoStr = "address not in Names: [0x%X]" % funcAddr
#   else:
#     funcNameAndAddrBothInNamesDict[funcName] = funcAddr
#     curInfoStr = "both in Names: [0x0%X] %s" % (funcAddr, funcName)
#   print("[%d/%d] %s" % (funcSymNum, validFunctionsSymbolCount, curInfoStr))

#   # isFuncInNames = isFuncNameInNames and isFuncAddrInNames
#   # if not isFuncInNames:
#   #   isAllFuncSymInNames = False
#   #   break
# # print("isAllFuncSymInNames=%s" % isAllFuncSymInNames)

# print("Total valid Functions symbol count: %d" % validFunctionsSymbolCount)
# print("  both name and address in Names count: %d" % len(funcNameAndAddrBothInNamesDict.keys()))
# print("  function name not in Names count: %d" % len(funcNameNotInNamesList))
# print("  function address not in Names count: %d" % len(funcAddrNotInNamesList))
# print("  both name and address not in Names count: %d" % len(funcNameAndAddrBothNotInNamesDict.keys()))

# for later omit duplicated symbol
funcSymDict_nameKey = {}
funcSymDict_addressKey = {}
for eachFuncSymDict in functionsSymbolDictList:
  eachFuncSymName = eachFuncSymDict["name"]
  eachFuncSymAddrStr = eachFuncSymDict["address"]
  eachFuncSymAddr = int(eachFuncSymAddrStr, base=16)

  # # for debug
  # isVerbose = True

  # # here makesure no duplicated (name or address) -> no need to check
  # if eachFuncSymName in funcSymDict_nameKey:
  #   if isVerbose:
  #     oldSameNameDict = funcSymDict_nameKey[eachFuncSymName]
  #     print("Not add for Functions dup name: old=%s <-> new=%s" % (oldSameNameDict, eachFuncSymDict))
  # else:
  #   funcSymDict_nameKey[eachFuncSymName] = eachFuncSymDict

  # if eachFuncSymAddr in funcSymDict_addressKey:
  #   if isVerbose:
  #     oldSameAddrDict = funcSymDict_addressKey[eachFuncSymAddr]
  #     print("Not add for Functions dup address: old=%s <-> new=%s" % (oldSameAddrDict, eachFuncSymDict))
  # else:
  #   funcSymDict_addressKey[eachFuncSymAddr] = eachFuncSymDict
  
  funcSymDict_nameKey[eachFuncSymName] = eachFuncSymDict
  funcSymDict_addressKey[eachFuncSymAddr] = eachFuncSymDict

print("len(funcSymDict_nameKey.keys())=%d" % len(funcSymDict_nameKey.keys()))
print("len(funcSymDict_addressKey.keys())=%d" % len(funcSymDict_addressKey.keys()))
# if two len not same with above validFunctionsSymbolCount -> need Attention -> exist duplicated function symbol

# # for debug
# isVerbose = False

totalNamesCount = 0
invalidNameCount = 0
dupInFuncCount = 0
namesSymbolDictList = []
nameTupleIterator = idautils.Names()
for (nameAddr, nameName) in nameTupleIterator:
  totalNamesCount += 1
  if nameName and (nameAddr != None):
    if enableDemangleName:
      nameName = ida_getDemangledName(nameName)

    isDupNameInFunc = nameName in funcSymDict_nameKey.keys()
    isDupAddrInFunc = nameAddr in funcSymDict_addressKey.keys()
    if isDupNameInFunc or isDupAddrInFunc:
      dupInFuncCount += 1
      if isVerbose:
        if isDupNameInFunc and isDupAddrInFunc:
          print("Dup name and address in functions for Names: [0x%X] %s" % (nameAddr, nameName))
        elif isDupNameInFunc:
          print("Dup name in functions for Names: %s" % nameName)
        elif isDupAddrInFunc:
          print("Dup address in functions for Names: [0x%X]" % nameAddr)
    else:
      nameAddrStr = "0x%X" % nameAddr
      curNamesSymbolDict = {
        "name": nameName,
        "address": nameAddrStr,
      }
      namesSymbolDictList.append(curNamesSymbolDict)
  else:
    invalidNameCount += 1
    if isVerbose:
      print("Omit: invalid Name for: [0x%X] %s" % (nameAddr, nameName))

namesSymbolCount = len(namesSymbolDictList)
print("namesSymbolCount=%s" % namesSymbolCount)

logSub("Merging Symbols")

idaSymbolDictList = functionsSymbolDictList + namesSymbolDictList
totalIdaSymbolCount = len(idaSymbolDictList)
print("totalIdaSymbolCount=%s" % totalIdaSymbolCount)

logMain("Summary Info")

print("Total IDA symbols count: %d" % totalIdaSymbolCount)
print("  Functions symbol count: %d" % validFunctionsSymbolCount)
print("    Total Functions count: %d" % totalFunctionsCount)
print("    Invalid Functions symbol count: %d" % invalidFunctionsSymbolCount)
print("  Names symbol count: %d" % namesSymbolCount)
print("    Total Names count: %d" % totalNamesCount)
print("    Duplicated Names count: %d" % dupInFuncCount)
print("    Invalid Names count: %d" % invalidNameCount)

if isExportToFile:
  print("Exporting %d IDA symbol to" % totalIdaSymbolCount)
  print("  folder: %s" % outputFolder)
  print("  file: %s" % outputFullFilename)
  outputFullPath = os.path.join(outputFolder, outputFullFilename)
  saveJsonToFile(outputFullPath, idaSymbolDictList)
  print("Export complete")
