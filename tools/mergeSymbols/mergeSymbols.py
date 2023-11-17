# Function: Merge symbols from exported from IDA (functions), restore-symbol restored, scanned Objc block
# Author: Crifan Li
# Update: 20231117

import os
import json
from datetime import datetime,timedelta
from datetime import time  as datetimeTime
import codecs
import copy

# import cxxfilt

# symNameList = [
#   "N3foo12BarExceptionE",
#   "_ZN7mangled3fooEd",
#   "_ZNSt22condition_variable_anyD2Ev",

#   # "s6FindMy15FMTaskSchedulerC6sharedACvau",
#   # "_s6FindMy15FMTaskSchedulerC6sharedACvau",
  
#   "_$s6FindMy15FMTaskSchedulerC6sharedACvau",
#   "_$sSo8NSBundleC15WAContactPickerE07contactC15ResourcesBundleABSgvgZ",
#   "_$sSo8NSBundleC15WAContactPickerE07contactC15ResourcesBundleABSgvsZ",
#   "_$sSo8NSBundleC15WAContactPickerE07contactC15ResourcesBundleABSgvMZ",
# ]
# for symName in symNameList:
#   # demangledSymName = cxxfilt.demangle(symName, external_only=False)
#   demangledSymName = cxxfilt.demangle(symName)
#   print("%s -> %s" % (symName, demangledSymName))

# print()

################################################################################
# Config & Settings & Const
################################################################################

# curAppName = "WhatsApp"
# # idaFunctionsSymbolFileName = "WhatsApp_IDAFunctionsSymbol_20231112_174504.json"
# # idaFunctionsSymbolFileName = "WhatsApp_IDAFunctionsSymbol_ImageBase0x100000000_20231114_114528.json"
# idaFunctionsSymbolFileName = "WhatsApp_IDAFunctionsSymbol_omitImportFunc_20231115_115215.json"
# restoreSymbolObjcSymbolFileName = "WhatsApp_objcNoDupSymbols_20231105.json"
# idaBlockSymbolFileName = "WhatsApp_block_symbol_20231027_114208.json"

curAppName = "SharedModules"
# idaFunctionsSymbolFileName = "SharedModules_IDAFunctionsSymbol_20231112_175710.json"
idaFunctionsSymbolFileName = "SharedModules_IDAFunctionsSymbol_omitImportFunc_20231115_220343.json"
restoreSymbolObjcSymbolFileName = "SharedModules_objcNoDupSymbols_20231108.json"
# idaBlockSymbolFileName = "SharedModules_block_symbol_20231027_153048.json"
idaBlockSymbolFileName = "SharedModules_blockSymbolsRenamed_20231117_220017.json"

################################################################################
# Global Variable
################################################################################

curFilePath = os.path.abspath(__file__)
curFolder = os.path.dirname(curFilePath)
print("curFilePath=%s, curFolder=%s" % (curFilePath, curFolder))

inputFolderName = os.path.join("input", curAppName)
idaFunctionsSymbolFile = os.path.join(curFolder, inputFolderName, idaFunctionsSymbolFileName)
restoreSymbolObjcSymbolFile = os.path.join(curFolder, inputFolderName, restoreSymbolObjcSymbolFileName)
idaBlockSymbolFile = os.path.join(curFolder, inputFolderName, idaBlockSymbolFileName)

################################################################################
# Util Function
################################################################################

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


def loadJsonFromFile(fullFilename, fileEncoding="utf-8"):
  """load and parse json dict from file"""
  with codecs.open(fullFilename, 'r', encoding=fileEncoding) as jsonFp:
    jsonDict = json.load(jsonFp)
    # logging.debug("Complete load json from %s", fullFilename)
    return jsonDict

################################################################################
# Main
################################################################################

# # for debug: rename block symbol name for same address
# blockSymList = loadJsonFromFile(idaBlockSymbolFile)
# blockSymNum = len(blockSymList)
# print("  blockSymNum=%s" % blockSymNum)

# blockNameAddrListDict = {}

# for eachBlockSym in blockSymList:
#   blockSymName = eachBlockSym["name"]
#   blockSymAddrStr = eachBlockSym["address"]
#   blockSymAddr = int(blockSymAddrStr, base=16)
#   if blockSymName in blockNameAddrListDict.keys():
#     existAddrList = blockNameAddrListDict[blockSymName]
#     existAddrList.append(blockSymAddr)
#     existAddrList.sort()
#   else:
#     addrList = [blockSymAddr]
#     blockNameAddrListDict[blockSymName] = addrList

# addrNewNameDict = {}
# sameNameDiffAddrCount = 0
# for eachSymName, eachSymAddrList in blockNameAddrListDict.items():
#   eachSymAddrListLen = len(eachSymAddrList)
#   if eachSymAddrListLen > 1:
#     sameNameDiffAddrCount += 1
#     for eachSymAddrNum, eachSymAddr in enumerate(eachSymAddrList, start=1):
#       newSymName = "%s_%d" % (eachSymName, eachSymAddrNum)
#       addrNewNameDict[eachSymAddr] = newSymName
#       print("[0x%X] = %s" % (eachSymAddr, newSymName))
# print("Found same name diff address: %d" % sameNameDiffAddrCount)

# renamedSameNameDiffAddrCount = 0
# for eachBlockSymDict in blockSymList:
#   blockSymName = eachBlockSymDict["name"]
#   blockSymAddrStr = eachBlockSymDict["address"]
#   blockSymAddr = int(blockSymAddrStr, base=16)
#   if blockSymAddr in addrNewNameDict.keys():
#     newBlockSymName = addrNewNameDict[blockSymAddr]
#     eachBlockSymDict["name"] = newBlockSymName
#     print("name: %s -> %s " % (blockSymName, newBlockSymName))
#     renamedSameNameDiffAddrCount += 1
# print("Has renamed for same name diff address: %d" % renamedSameNameDiffAddrCount)


outputBaseFilename = "mergedSymbols"
outputFilename = "%s_%s_%s.json" % (curAppName, outputBaseFilename, getCurDatetimeStr())
# print("outputFilename=%s" % outputFilename)
outputFullFilename = os.path.join(curFolder, "output", outputFilename)
# print("outputFullFilename=%s" % outputFullFilename)

print("1. Load IDA exported symbols: %s" % idaFunctionsSymbolFileName)
idaFunctionsSymbolList = loadJsonFromFile(idaFunctionsSymbolFile)
print("  len(idaFunctionsSymbolList)=%s" % len(idaFunctionsSymbolList))

print("  Parsing IDA symbols")

idaFunctionsSymbolDict = {}
for eachSymbolDict in idaFunctionsSymbolList:
  symName = eachSymbolDict["name"]
  symAddStr = eachSymbolDict["address"]
  # to support hex, both capital and lowercase
  symAddInt = int(symAddStr, base=16)
  symSizeStr = eachSymbolDict["size"]
  symSizeInt = int(symSizeStr, base=16)

  idaFunctionsSymbolDict[symName] = {
    "address": symAddInt,
    "size": symSizeInt,
  }

idaFunctionsSymbolDictKeys = idaFunctionsSymbolDict.keys()
print("  len(idaFunctionsSymbolDictKeys)=%s" % len(idaFunctionsSymbolDictKeys))

mergedSymbolsDict = copy.deepcopy(idaFunctionsSymbolDict)
mergedSymbolsDictKeys = mergedSymbolsDict.keys()
print("  len(mergedSymbolsDictKeys)=%s" % len(mergedSymbolsDictKeys))

print("2. Merge restore-symbol restored Objc symbols: %s" % restoreSymbolObjcSymbolFileName)
# rs = restore-symbol
rsObjcSymbolList = loadJsonFromFile(restoreSymbolObjcSymbolFile)
rsObjcSymbolNum = len(rsObjcSymbolList)
print("  rsObjcSymbolNum=%s" % rsObjcSymbolNum)

SymbolNum_RsInIda = 0
SymbolNum_RsInIda_AddrSame = 0
SymbolNum_RsInIda_AddrNotSame = 0
SymbolNum_RsNotInIda = 0
for curRsObjSymDict in rsObjcSymbolList:
  rsSymName = curRsObjSymDict["name"]
  rsSymAddrStr = curRsObjSymDict["address"]
  rsSymAddr = int(rsSymAddrStr, base=16)
  rsSymTypeStr = curRsObjSymDict["type"]
  rsSymType = int(rsSymTypeStr, base=16)

  # for debug
  if not rsSymType:
    print("  Abnormal: restore-symbol symbol no type for: %s" % curRsObjSymDict)

  if rsSymName in mergedSymbolsDictKeys:
    SymbolNum_RsInIda += 1
    idaSymDict = mergedSymbolsDict[rsSymName]
    idaSymAddr = idaSymDict["address"]
    if (rsSymAddr == idaSymAddr): # if not same -> use(keep) IDA symbol
      SymbolNum_RsInIda_AddrSame += 1
      idaSymDict["type"] = rsSymType
    else:
      SymbolNum_RsInIda_AddrNotSame += 1
  else:
    SymbolNum_RsNotInIda += 1
    mergedSymbolsDict[rsSymName] = {
      "address": rsSymAddr,
      "type": rsSymType,
    }

print("  Total restored symbol number: %s" % rsObjcSymbolNum)
print("   in IDA: %s" % SymbolNum_RsInIda)
print("     in IDA, same address: %s" % SymbolNum_RsInIda_AddrSame)
print("     in IDA, not same address: %s" % SymbolNum_RsInIda_AddrNotSame)
print("   not in IDA: %s" % SymbolNum_RsNotInIda)

print("3. Merge IDA scanned objc block symbols: %s" % idaBlockSymbolFileName)
idaBlockSymbolList = loadJsonFromFile(idaBlockSymbolFile)
idaBlockSymbolNum = len(idaBlockSymbolList)
print("  idaBlockSymbolNum=%s" % idaBlockSymbolNum)

# Note: above symbol list have changed, so need updated
mergedSymbolsDictKeys = mergedSymbolsDict.keys()

# generate new address: name dict, for later use
mergedSymbolsAddrNameDict = {}
for eachSymName, eachSymDict in mergedSymbolsDict.items():
  eachSymAddr = eachSymDict["address"]
  mergedSymbolsAddrNameDict[eachSymAddr] = eachSymName

toRemoveSameAddrSymbolNameDict = []

SymbolNum_BlockInMerged = 0
SymbolNum_BlockInMerged_AddrSame = 0
SymbolNum_BlockInMerged_AddrNotSame = 0
SymbolNum_BlockNotInMerged = 0
SymbolNum_BlockNotInMerged_SameAddr = 0
for blockSymDict in idaBlockSymbolList:
  blockSymName = blockSymDict["name"]
  blockSymAddrStr = blockSymDict["address"]
  blockSymAddr = int(blockSymAddrStr, base=16)

  if blockSymName in mergedSymbolsDictKeys:
    SymbolNum_BlockInMerged += 1
    mergedSymDict = mergedSymbolsDict[blockSymName]
    mergedSymAddr = mergedSymDict["address"]
    if (blockSymAddr == mergedSymAddr):
      # if same address -> use/keep merged symbol
      SymbolNum_BlockInMerged_AddrSame += 1
    else:
      print("Same name=%s, but diff addr: merged=0x%X vs block=0x%X" % (blockSymName, mergedSymAddr, blockSymAddr))
      SymbolNum_BlockInMerged_AddrNotSame += 1
  else:
    SymbolNum_BlockNotInMerged += 1

    # if not same name -> use/keep block symbol
    # for eachSymbolName in mergedSymbolsDictKeys:
    #   echSymbolDict = mergedSymbolsDict[eachSymbolName]
    #   eachSymbolAddr = echSymbolDict["address"]
    #   if eachSymbolAddr == blockSymAddr:
    #     toRemoveSameAddrSymbolNameDict.append(eachSymbolName)

    # assume only one, if exist same address
    if blockSymAddr in mergedSymbolsAddrNameDict.keys():
      SymbolNum_BlockNotInMerged_SameAddr += 1
      sameAddrSymName = mergedSymbolsAddrNameDict[blockSymAddr]
      toRemoveSameAddrSymbolNameDict.append(sameAddrSymName)

    mergedSymbolsDict[blockSymName] = {
      "address": blockSymAddr,
    }

for eachToRemoveSymName in toRemoveSameAddrSymbolNameDict:
  mergedSymbolsDict.pop(eachToRemoveSymName)

print("  Total block symbol number: %s" % idaBlockSymbolNum)
print("   in merged: %s" % SymbolNum_BlockInMerged)
print("     in merged, same address: %s" % SymbolNum_BlockInMerged_AddrSame)
print("     in merged, not same address: %s" % SymbolNum_BlockInMerged_AddrNotSame)
print("   not in merged: %s" % SymbolNum_BlockNotInMerged)
print("     same address(replaced name): %s" % SymbolNum_BlockNotInMerged_SameAddr)

print("4. Output final merged symbols : %s" % outputFilename)
outputSymbolList = []
for symName, symDict in mergedSymbolsDict.items():
  outputSymAddr = symDict["address"]
  outputSymAddrStr = "0x%X" % outputSymAddr
  outputSymDict = {
    "name": symName,
    "address": outputSymAddrStr,
  }

  if "type" in symDict:
    outputSymType = symDict["type"]
    if outputSymType != None:
      outputSymTypeStr = "0x%X" % outputSymType
      outputSymDict["type"] = outputSymTypeStr
    else:
      # for debug
      print("Abnormal: type is none for %s,%s" % (symName, symDict))

  if "size" in symDict:
    outputSymSize = symDict["size"]
    if outputSymSize != None:
      outputSymSizeStr = "0x%X" % outputSymSize
      outputSymDict["size"] = outputSymSizeStr
    else:
      # for debug
      print("Abnormal: size is none for %s,%s" % (symName, symDict))

  outputSymbolList.append(outputSymDict)

sortedOutputSymbolList = sorted(outputSymbolList, key=lambda eachDict: int(eachDict["address"], base=16))

mergedSymbolNum = len(sortedOutputSymbolList)
print("  Exporting %d symbols to file %s" % (mergedSymbolNum, outputFilename))
saveJsonToFile(outputFullFilename, sortedOutputSymbolList)
print("  Exported final merged symbol file %s" % outputFullFilename)

print("")
