//Javascript functions
function loadXMLDoc(doc_name)
{
    if(window.XMLHttpRequest){
        xhttp=new XMLHttpRequest();
    }
    else{
        xhttp=new ActiveXObject("Microsoft.XMLHTTP");
    }

    xhttp.open("GET",doc_name,false);
    xhttp.send();
    return xhttp.responseXML;
}

//Parses xml as string
function loadXMLString(txt)
{
    if(window.DOMParser){
        parser=new DOMParser();
        xmlDoc=parser.parserFromString(txt,"text/xml");
    }
    else //Internet Explorer
    {
        xmlDoc=new ActiveXObject"Microsoft.XMLDOM");
        xmlDoc.async=false;
        xmlDoc.loadXML(txt);
    }
    return xmlDoc;
}
