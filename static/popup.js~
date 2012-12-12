var popupstatus = 0;

function loadPopup(){
    if(popupstatus==0){
        $("#backgroundPopup").css({
            "opacity": "0.7"

        });
        $("#backgroundPopup").fadeIn("fast");
        $("#popupContent").fadeIn("fast");
        popupstatus = 1;
    }
}

function disablePopup(){
    if(popupstatus==1){
        $("#backgroundPopup").fadeOut("fast");
        $("#popupContent").fadeOut("fast");
        popupstatus=0;
    }
}

function centerPopup(){
    var w_width = document.documentElement.clientWidth;
    var w_height = document.documentElement.clientHeight;
    var p_height = $("#popupContent").height();
    var p_width = $("#popupContent").width();
    $("#popupContent").css({
        "position":"absolute",
        "top": w_height/2-p_height/2,
        "left": w_width/2 - p_width/2
    });

    $("#backgroundPopup").css({
        "height": w_height
    });
}
