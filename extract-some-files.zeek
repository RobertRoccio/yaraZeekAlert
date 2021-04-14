global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe", 
    ["text/plain"] = "txt", 
    ["text/html"] = "html", 
    ["application/zip"] = "zip", 
    ["application/x-7z-compressed"] = "7z", 
    ["application/x-rar"] = "rar", 
    ["application/x-rar-compressed"] = "rar", 
    ["application/xdmg"] = "dmg", 
    ["application/msword"] = "doc", 
    ["application/msexcel"] = "xls", 
    ["application/mspowerpoint"] = "ppt", 
    ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx", 
    ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx", 
    ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] ="pptx", 
    ["application/pdf"] = "pdf", 
    ["text/rtf"] = "rtf", 
} &default =""; 

event file_sniff(f: fa_file, meta: fa_metadata) 
    { 
    if ( ! meta?$mime_type ) 
        return; 

    if ( ! ( meta$mime_type == "application/x-dosexec" || meta$mime_type == "text/plain" || 
    meta$mime_type == "text/html" || meta$mime_type == "application/xdmg" || meta$mime_type 
    == "application/zip" || meta$mime_type == "application/x-7z-compressed" || meta$mime_type 
    == "application/x-rar" || meta$mime_type == "application/x-rar-compressed" || meta$mime_type 
    == "application/msword" || meta$mime_type == "application/msexcel" || meta$mime_type 
    == "application/mspowerpoint" || meta$mime_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document" || 
    meta$mime_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" || meta$mime_type 
    == "application/vnd.openxmlformats-officedocument.presentationml.presentation" || meta$mime_type == "text/rtf" || 
    meta$mime_type == "application/pdf")) 
        return; 

    local ext = ""; 

    if ( meta?$mime_type ) 
        ext = ext_map[meta$mime_type]; 
    
    local fname = fmt("INSTALL-DIR/extracted-files/%s-%s.%s", f$source, f$id, ext); 
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]); 
    }