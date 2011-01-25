# Office2007 and OpenXML FileFormat Forensics Helper - 2011
#
# Author: Giuseppe 'evilcry' Bonfa
# E-Mail: /
# Website: http://evilcodecave.blogspot.com

import os
import sys
import zipfile

from BeautifulSoup import BeautifulStoneSoup, Tag
from optparse import OptionParser

def main():
    print("Parse and Carve Office2007 Informations")
    print("=======================================")

    usage = "%Prog Deflated_Directory\n"
    description = "Parse Office2007 informations\n"

    parser = OptionParser(usage = usage, description = description,
    version = "1.0")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        print("Specify an Office2007 file")
    else:
        fileName = args[0]
        
        if os.path.isfile(fileName):
                        
            defArch = deflater(fileName)
            print("=======================================")
            
            if defArch is 0:
                print("[-] Error - Closing")
            else:
                if os.name == 'nt':
                    oslash = '\\'
                elif os.name == 'posix':
                    oslash = '/'
                
                if fileName.endswith('.docx'):
                    wordParser(defArch, oslash)
                elif fileName.endswith('.pptx'):
                    pptParser(defArch, oslash)
                elif fileName.endswith('.xlsx'):
                    excelParser(defArch, oslash)
                elif fileName.endswith('.odt'):
                    openofficeParser(defArch, oslash)
                elif fileName.endswith('.odp'):
                    openofficeParser(defArch, oslash)
                elif fileName.endswith('ods'):
                    openofficeParser(defArch, oslash)
                             
        else:
            print("This is not a Directory")
            sys.exit(-1)
            
    sys.exit(1)
    
# ##############################################################################
def deflater(fileName):
    try:
        if zipfile.is_zipfile(fileName) is False:
            print("This is not a Valid Office2007 FileFormat")
            return 0
        else:
            if os.name == 'nt':
                defArch = os.curdir + "\\" + fileName[:len(fileName)-5]
            elif os.name == 'posix':
                defArch = os.curdir + "/" + fileName[:len(fileName)-5]
            
            if not os.path.exists(defArch):
                os.mkdir(defArch)
                deflater = zipfile.ZipFile(fileName)
                deflater.printdir()
                deflater.extractall(defArch)
                deflater.close()
                return defArch
            else:
                print("Directory Already Exists")
                return 0
    except:
        print("Generic Error Happened While Deflaing")
        return 0
    return

def wordParser(defArch,oslash):
    try:
        
        docProps = defArch + oslash + 'docProps' + oslash
        
        if os.path.exists(docProps) is False:
            print("This Document Does Not Contain MetaData Informations")
            return False                  
            
        fapps = open(docProps + 'app.xml','r')
        fxml = fapps.read()
        fapps.close()
        
        print("\n === MetaData === \n")    
        soup = BeautifulStoneSoup(fxml)
        
        Application = soup.properties.application
        if Application is not None:
            print("Application => " + Application.contents[0])
        
        Security = Application.next
        if Security is not None:
            print("Doc Security => " + Security.contents[0])
        
        AppVersion = soup.properties.appversion
        if AppVersion is not None:
            print("AppVersion => " + AppVersion.contents[0])
        
        fcore = open(docProps + 'core.xml','r')
        fxml = fcore.read()
        fapps.close()
        
        print("\n === Core Informations === \n")
        
        soup = BeautifulStoneSoup(fxml)
        
        creator = soup.find("dc:creator")
        if creator is not None:
            print("Creator => " + creator.contents[0])
            
        lastmodby = creator.next
        if lastmodby is not None:
            print("Last Modified By => " + lastmodby.contents[0])
        
        revision = lastmodby.next
        if revision is not None:
            print("Revision => " + revision.contents[0])
        
        lastPrint = revision.next
        if lastPrint is not None:
            print("Last Print => " + lastPrint.contents[0])
        
        dctCreated = lastPrint.next
        if dctCreated is not None:
            print("DCTerm Created => " + dctCreated.contents[0])
            
        dctModified = dctCreated.next
        if dctModified is not None:
            print("DcTerm Modified => " + dctModified.contents[0])
        
        print("\n ===Unique Markers from Footnotes=== \n")
                
        footNotes = defArch + oslash + 'word' + oslash + 'footnotes.xml'
        
        ffoot = open(footNotes,'r')
        fxml = ffoot.read()
        ffoot.close()
        
        soup = BeautifulStoneSoup(fxml)
        unique_markers = soup.find("w:p")
        if unique_markers is not None:
            print("RevisionSaveID R => " + unique_markers["w:rsidr"])
            print("RevisionSaveID R Default => " + unique_markers["w:rsidrdefault"])
            print("Revision Save ID P => " + unique_markers["w:rsidp"])     
    
    except:
        print("Error While Parsing Word File")
        return False    
            
    return True

def pptParser(defArch,oslash):
    try:
        docProps = defArch + oslash + 'docProps' + oslash
        
        if os.path.exists(docProps) is False:
            print("This File Does Not Contain MetaData Informations")
            return False
        
        fapps = open(docProps + 'app.xml','r')
        fxml = fapps.read()
        fapps.close()
        
        print("\n === MetaData === \n")  
        soup = BeautifulStoneSoup(fxml)
        Application = soup.properties.application
        if Application is not None:
            print("Application => " + Application.contents[0])
        
        PresoFormat = Application.next
        if PresoFormat is not None:
            print("Presentation Format => " + PresoFormat.contents[0])
        
        Slides = soup.properties.slides
        if Slides is not None:
            print("Number Of Slides => " + Slides.contents[0])
        
        Notes = soup.properties.notes
        if Notes is not None:
            print("Notes => " + Notes.contents[0])
        
        HSlides = Notes.next
        if HSlides is not None:
            print("Hidden Slides => " + HSlides.contents[0])
        
        company = soup.properties.company
        if company is not None:
            print("Company => " + company.contents[0]) 
                   
        print("\n ===Core Informations===\n")
        fcore = open(docProps + 'core.xml','r')
        fxml = fcore.read()
        fcore.close
        
        soup = BeautifulStoneSoup(fxml)
        
        Title = soup.find("dc:title")
        if Title is not None:
            print("Title => " + Title.contents[0])
        
        lastModBy = Title.next
        if lastModBy is not None:
            print("Last Modified By => " + lastModBy.contents[0])
        
        revision = lastModBy.next
        if revision is not None:
            print("Revision => " + revision.contents[0])
        
        termModified = revision.next
        if termModified is not None:
            print("Terms Modified => " + termModified.contents[0])  
        
        print("\n ===Unique Identifiers=== \n")      
        
    except:
        print("Error While Parsing Ppt File")
        return False
    return

def excelParser(defArch,oslash):
    try:
        docProps = defArch + oslash + 'docProps' + oslash
        
        if os.path.exists(docProps) is False:
            print("This File Does Not Contain MetaData Informations")
            return False
        
        fapps = open(docProps + 'app.xml','r')
        fxml = fapps.read()
        fapps.close()
        
        print("\n === MetaData === \n")  
        soup = BeautifulStoneSoup(fxml)
        Application = soup.properties.application
        if Application is not None:
            print("Application => " + Application.contents[0])
        
        docSecurity = Application.next
        if docSecurity is not None:
            print("Doc Security => " + docSecurity.contents[0])
        
        Company = soup.properties.company
        if Company is not None:
            print("Company => " + Company.contents[0])
        
        print("\n ===Core Informations===\n")
        fcore = open(docProps + 'core.xml','r')
        fxml = fcore.read()
        fcore.close()
        
        soup = BeautifulStoneSoup(fxml)
        
        creator = soup.find("dc:creator")
        if creator is not None:
            print("Creator => " + creator.contents[0])
        
        lastModBy = creator.next
        if lastModBy is not None:
            print("Last Modified By => " + lastModBy.contents[0])
        
        created = lastModBy.next
        if created is not None:
            print("Created => " + created.contents[0])
        
        modified = created.next
        if modified is not None:
            print("Modified => " + modified.contents[0])
        
        wbook = defArch + oslash + 'xl' + oslash + 'workbook.xml'
        
        fwb = open(wbook, 'r')
        fxml = fwb.read()
        fwb.close()
        
        print("\n ===WorkBook=== \n")

        soup = BeautifulStoneSoup(fxml)
        
        fileVer = soup.workbook.fileversion
        if fileVer is not None:
            print("File Version => " + fileVer["lastedited"])
            print("Lowest Edited => " + fileVer["lowestedited"])
            print("Rup Build => " + fileVer["rupbuild"])
        
        print("\n ===Unique Identifiers=== \n")
        
    except:
        print("Error While Parsing Xls File")
        return False
    return
    
def openofficeParser(defArch,oslash):
    try:
        metadata = defArch + oslash + 'meta.xml'
        
        print("\n ===MetaData=== \n")
                
        fmeta = open(metadata,'r')
        fxml = fmeta.read()
        fmeta.close()
        
        soup = BeautifulStoneSoup(fxml)
        
        base_metadata = soup.find("office:meta")
        if base_metadata is not None:
            init_creator = soup.find("meta:initial-creator")
        else:
            return False
        
        if init_creator is not None:
            print("Initial Creator => " + init_creator.contents[0])
                
        creation_date = soup.find("meta:creation-date")
        
        if creation_date is not None:
            print("Creation Date => " + creation_date.contents[0])
        
        date = soup.find("dc:date")
        if date is not None:
            print("Date => " + date.contents[0])
        
        creator = soup.find("dc:creator")
        if creator is not None:
            print("Creator => " + creator.contents[0])
        
        editing_duration = soup.find("meta:editing-duration")
        if editing_duration is not None:
            print("Editing Duration => " + editing_duration.contents[0])
            
        editing_cycles = soup.find("meta:editing-cycles")
        if editing_cycles is not None:
            print("Editing Cycles => " + editing_cycles.contents[0])

        generator = soup.find("meta:generator")
        if generator is not None:
            print("Document Generator => " + generator.contents[0])
        
        description = soup.find("dc:description")
        if description is not None:
            print("Description => " + description.contents[0])
            
        keyword = soup.find("meta:keyword")
        if keyword is not None:
            print("Keyword => " + keyword.contents[0])
            
        subject = soup.find("dc:subject")
        if subject is not None:
            print("Subject => " + subject.contents[0])
            
        title = soup.find("dc:title")
        if title is not None:
            print("Title => " + title.contents[0])          
                
    except:
        print("Error While Parsing ODT File")
        return False
    return True

if __name__ == '__main__':
    main()
