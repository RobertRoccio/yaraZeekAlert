rule Office_doc_Execution {
    meta:
            author= "David Bernal - Scilabs"
            description = "Detects Microsoft Office docs with strings related to code execution"
            license = "https://creativecommons.org/licenses/by-nc/4.0/"
    strings:
            $run1 = ".Run"
            $run2 = ".ShellExecute"
            $macro1 = "ThisDocument"
            $macro2 = "Project"
    condition:
            uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1 and
            all of ($macro*) and 1 of ($run*)
}           

rule Office_doc_AutoOpen {
     meta: 
            author = "David Bernal - Scilabs" 
            description = "Detects Microsoft Office documents with macro code, shell and function names related to automatic code execution" 
            license = "https://creativecommons.org/licenses/by-nc/4.0/"
            revision = "2" 
     strings: 
            $auto1 = "AutoOpen" 
            $auto2 = "AutoClose" 
            $auto3 = "Document_Open" 
            $macro1 = "ThisDocument" 
            $macro2 = "Project" 
    condition: 
            uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1 and 
            all of ($macro*) and 1 of ($auto*) 
}
rule Yara_Test {
        strings:
                $string1 = "sample"
        condition:
                any of them
}