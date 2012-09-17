function initProfile(){
	$.get("CMD",  { "method" : "profile", "id" : $("#uid").html() }, 
		function(data){
            $('.sname').html(data.name);
            $('.surname').html(data.surname);
            $('.sex').html(data.sex);
            $('.birth').html(data.birth);
            $('.birthP').html(data.birthP);
            $('.nationality').html(data.nationality);
            $('.mail').html(data.mail);
            $('.phone').html(data.phone);
            $('.mobile').html(data.mobile);
            $('.company').html(data.company);
            $('.department').html(data.department);
            $('.role').html(data.role);
            $('.companymail').html(data.companymail);
            $('.companytel').html(data.companytel);
            $('.companymobiletel').html(data.companymobiletel);
            $('.imgavatar').attr("src","./nowhere/otherprof_" + data.uid + ".jpg"); // triggers the HTTP GET request
            
	}, 'json');
	friendRequest();
	getfriendbadges();
}

function getfriendbadges(){
	$.get("CMD",  { "method" : "getFriendBadges", "uid":$("#uid").html()}, 
		function(data){
			$('#badgeOptions').html(data);            
	}, 'text');
}

function initContacts() {
	$.get("CMD",  { "method" : "contacts" }, 
		function(data){
			$('#friendList').html(data);            
	}, 'text');
	friendRequest();
}
function initFRA(status) {
	
	$.get("CMD",  { "method" : "getBadgeCheckBox", "userId":$("#userId").html(), "userName":$("#userName").html(), "status":$("#status").html()}, 
		function(data){
			$('#badgeOptions').html(data);            
	}, 'text');
}

function initADV() {
	
	$.get("CMD",  { "method" : "initKeyAdvertise", "uid":$("#uid").html()}, 
		function(data){
			$('#badgeOptions').html(data);            
	}, 'text');
}
function closefra(){
	 //alert("closed fra called")
	 add();
	 window.close();
	 location.reload(true)
}

function closeAdv(){
	 //alert("closed adv called")
	 sendBadge();
	 window.close();
}
function closeConfirmEdit(){
	 //alert("closeConfirmEdit called");
	 confirmEdit();
	 location.reload(true);
}
function initGallery(){
	
	if($("#uid").html() == "-1"){
		var pic = "./nowhere/otherprof_"+$("#uid").html()+".jpg";
		$('#tweetImg').attr("src",pic);
	}

	uid=$("#uid").html()
	aid=$("#aid").html()
	pid=$("#pid").html()
	if(pid!=null)
		showPicture("Show Picture Please", pid,uid)
	else if(aid!=null)
		showAlbum("Show Album", uid, aid, '0')
	else
		getGalleryAlbums('I need Gallery Albums',uid,0);
}
function inituserBadge(){
	//alert("inituserBadge");
	$.get("CMD",  { "method" : "getCommentAccessBadges", "uid":$("#uid").html(), "threadid":$("#threadid").html()}, 
		function(data){
			$('#badgeOptions').html(data);            
	}, 'text');
	
}
function initPodium(isPodium) {	
   // var txtMessage;
	//txtMessage = window.prompt("Please add a personal message. This message together with you public profile will be sent to  as a friendship advertisement!", "I would like to add you as a friend");
	var isSquare = "yes"
    if (isPodium)
        isSquare = "no"
	$.get("CMD",  { "isSquare" : isSquare, "method" : "podium","id" : $("#uid").html() }, 
		function(data){
			$('#tweetContent').html(data);            
	}, 'text');
	
	$.get("CMD",  { "isSquare" : isSquare, "method" : "threads", "badge":$("#badge").html(),"id" : $("#uid").html() }, 
		function(data){
			$('#wall').html(data);            
	}, 'text');
    Getbadge(isSquare);	
	var pic = "./nowhere/otherprof_"+$("#uid").html()+".jpg";
	$('#tweetImg').attr("src",pic);
	friendRequest();
}

function Getbadge(isSquare){
	$.get("CMD", { "method" : "getBadge" ,"isSquare":isSquare,"id" : $("#uid").html()},
		function(data){
            $("#badgeList").html(data);
	}, 'text');
}

function friendRequest(){
	$.get("CMD", { "method" : "fRequest" },
		function(data){
            $("#quickList").html(data);
	}, 'text');
}
function friendRem(Ruid){
						
	$.get("CMD", { "method" : "friendRem" ,'ruid':Ruid});
	
}

function tweet(){
	$.get("CMD", { "method" : "tweet", "word": $("#newTweet").val() } );
}

function retrieve(){
	$.get("CMD", { "method" : "retrieve", "word": $("#prrText").val() } );
}

function loading(){
	$("#quickList").html("<img src=\"img/loading.gif\" width=100 height=100>");
}

function find(){
	
	if($("#dhtKey").val()!="")
  {
  $("#quickList").html("<img class=\"loading\" src=\"img/loading.gif\">");
  	$.get("CMD", { "method" : "find", "key": $("#dhtKey").val() },
  		function(data){
              $("#quickList").html(data);
  	}, 'text');
  }
  else{
  alert("Please enter a username")
  }
}

function edit() {
	if($("#uid").html() == "-1"){
		alert("Please specify a path for your avatar.")
		$('.txtEdit').show();
		$('.buttonconfirm').show();
		$('.buttoncancel').show();
		$('#imageselector').show();
	
		$('#email').val($('.mail').html());
			$('#ephone').val($('.phone').html());
			$('#emobile').val($('.mobile').html());

		$('#ecompany').val($('.company').html());
			$('#edepartment').val($('.department').html());
			$('#erole').val($('.role').html());

		$('#ecompanymail').val($('.companymail').html());
			$('#ecompanytel').val($('.companytel').html());
			$('#ecompanymobiletel').val($('.companymobiletel').html());
	}
}
function logout(){
	$.get("CMD", { "method" : "logout" } );
	
	
 }
function confirmEdit(){
	//alert("ConfirmEdit called");
	$.get("CMD",  { "method" : "edit", mail: $("#email").val(), phone: $("#ephone").val(), mobile: $("#emobile").val(), company: $("#ecompany").val(), department: $("#edepartment").val(), role: $("#erole").val(),companymail: $(
"#ecompanymail").val(), companytel: $("#ecompanytel").val(), companymobiletel: $("#ecompanymobiletel").val(), picture: $("#imageselector").val() }, 
		function(data){
			$('.txtEdit').hide();
			$('.buttonconfirm').hide();
			$('.buttoncancel').hide();
			$('#imageselector').hide();
            
            $('.mail').html($('#email').val());
            $('.phone').html($('#ephone').val());
            $('.mobile').html($('#emobile').val()); 
	    
	    $('.company').html($('#company').val());
            $('.department').html($('#edepartment').val());
            $('.role').html($('#erole').val());
            
	    $('.companymail').html($('#ecompanymail').val());
            $('.companytel').html($('#ecompanytel').val());
            $('.companymobiletel').html($('#ecompanymobiletel').val());
            
            $('.imgavatar').attr("src",data);  	// triggers the HTTP GET request         
	}, 'text');	
	alert("Your profile information has been updated.");
}

function cancelEdit(){
	$('.txtEdit').hide();
	$('.buttonconfirm').hide();
	$('.buttoncancel').hide();
	$('#imageselector').hide();
}
function uploadPicture(threadid,uidowner,aid){
alert($('#photoPath').val());
	if($('#photoPath').val()!="Upload new Photo"){
		//pct=$('#photoId').val();
		path=$('#photoPath').val();
		desc=$('#discription').val();
		$.get("CMD", { "uidowner" : uidowner,"aid":aid,"method" : "uploadPCT", "path": path,"desc":desc, "threadid" : threadid, "id" : $("#uid").html()  },
		function(data){
           $('#gallery').html(data);  
	}, 'text');
		showAlbum('updating Album',uidowner,aid);
		
	}
	
}
function uploadPicture2(threadid,data,bid,gid,aid){
	if($('#photoId').val()!="Upload new Photo"){
		var vars = $('#UploadPhoto').serialize();
		pct=$('#photoId').val();
		desc=$('#discription').val();
		pdata=$('#pdata').val();
		$.get("CMD", { "pdata":data, "bid" : bid,"gid":gid,"aid":aid, "method" : "uploadPCT", "name": pct,"desc":desc, "threadid" : threadid, "id" : $("#uid").html()  },
		function(data){
           $('#wall').html(data);  
	}, 'text');
		//showAlbum('updating Album',gid,aid);
		
	}
	
}
function closeInsertComment(){
	var b=" ";
	chkbox=$('input:radio:checked');
	if (chkbox.length == 0) { //esko: no badge messages allowed
		alert("You must chose a badge, please try again");
		inituserBadge()
		}
	else {
		for (i=0;i<chkbox.length;i++)
			b+=chkbox[i].value+' ';
        insertComment2($("#threadid").html(), 0,decodeURIComponent($("#post").html()),b);
		/*insertComment2($("#threadid").html(), $("#isPodium").html(),$("#post").html(),b);*/
		window.close();
	}
}
function insertComment(threadid, isPodium){
	
    var post = "";
    if (threadid == "AnewThread")
        post = $('#newTweet').val();
    else
        post = $('#newPost' + threadid).val();
	if($("#badge").html()!="Square"){
		insertComment2(threadid, isPodium,post,$("#badge").html())
	}else{
		link="userBadge.html#uid="+$("#uid").html()+"?#isPodium="+isPodium+"?#threadid="+threadid+"?#post="+post+"?"
		window.showModalDialog(link,null,'dialogWidth:275px; dialogHeight:250px; center:yes; scroll:no; help:no; status:no; resizable:no');
		//alert("insert Comment 1");
		location.reload(true);
	}
}
function insertComment2(threadid, isPodium,post,badge){
    /*alert("threadid: "+threadid+" isPodium: "+isPodium+" post: "+post+"badge "+badge)*/
	var isSquare = "yes";
    if (isPodium)
        isSquare = "no";
    /*var post = "";
    if (threadid == "AnewThread")
        post = $('#newTweet').val();
    else
        post = $('#newPost' + threadid).val();*/
	$.get("CMD", { "isSquare" : isSquare, "method" : "insert", "post": post, "threadid" : threadid, "badge" : badge,"id" : $("#uid").html()  },
		function(data){
           $('#wall').html(data);  
	}, 'text');
	//alert("method insert called for post"+unescape(post))
	alert("Your message has been posted")
}

function addAlbum(threadid){
 
 	name = $('#albumName').val();
	$.get("CMD", { "thumb" : 0, "name":name, "method" : "addAlbum", "threadid" : threadid, "id" : $("#uid").html()  },
		function(data){
           $('#gallery').html(data);  
	}, 'text');
	getGalleryAlbums('I need Gallery Albums',$("#uid").html(),0);
}
function addGallery(threadid, bid){
 
 	name = $('#galleryName').val();
	$.get("CMD", { "bid" : bid, "name":name, "method" : "addGallery", "threadid" : threadid, "id" : $("#uid").html()  },
		function(data){
           $('#gallery').html(data);  
	}, 'text');
	getGalleryAlbums('I need Gallery Albums',$("#uid").html(),0);
}
function showAlbum(threadid, uidowner, aid, aname, pid){

	$.get("CMD", { "uidowner" : uidowner, "aid" : aid, "aname" : aname, "pid" : pid, "method" : "showAlbum", "threadid" : threadid, "id" : $("#uid").html()  },
		function(data){
           $('#gallery').html(data);   
	}, 'text');

	$.get("CMD", { "uidowner" : uidowner, "aid" : aid, "aname" : aname, "method" : "showAlbumBadges", "threadid" : threadid, "id" : $("#uid").html()  },
		function(data){
           $('#friendRequest').html(data);   
	}, 'text');
}
function showPicture(threadid, pid,uidowner, aid, aname){
 
	$.get("CMD", { "pid" : pid, "uidowner" : uidowner, "aid" : aid, "aname" : aname, "method" : "showPicture", "threadid" : threadid, "id" : $("#uid").html()  },
		function(data){
           $('#gallery').html(data);
		   $('#friendRequest').html('');  
	}, 'text');
}


function getGalleryAlbums(threadid,uid,aid){
    
	$.get("CMD", { "uid" : uid, "aid" : aid, "method" : "galleryAlbums", "threadid" : threadid  },
		function(data){
           $('#gallery').html(data);
           $('#friendRequest').html('');  		   
	}, 'text');
}

function mousePos(e) {
    this.x = 0;
    this.y = 0;

    if (!e)
        e = window.event;

    if (e.pageX || e.pageY) {
        this.x = e.pageX;
        this.y = e.pageY;
    }
    else if (e.clientX || e.clientY) {
        this.x = e.clientX + document.body.scrollLeft + document.documentElement.scrollLeft;
        this.y = e.clientY + document.body.scrollTop + document.documentElement.scrollTop;
    }
}

function showInfoBox(htmlValue, e) {
    var verCorrection = -40;
    var horCorrection = 10;
    var pos = new mousePos(e);
    var infoBox = document.getElementById("infoBox");

    infoBox.style.display = "block";
    infoBox.style.top = pos.y + verCorrection + "px";
    infoBox.style.left = pos.x + horCorrection + "px";
    infoBox.innerHTML = htmlValue;
}

function hideInfoBox() {
    var infoBox = document.getElementById("infoBox");
    infoBox.style.display = "none";
}
//userId, userName, status
function add() {
	//alert("add called")
	var b="";
	chkbox=$('input:checkbox:checked');
	for (i=0;i<chkbox.length;i++)
		b+=chkbox[i].value+' ';
	txtMessage=$("#msg").val();
		$.get("CMD", { "method" : "sendFA", "userId": $("#userId").html(), "userName": $("#userName").html(),"status": $("#status").html(), "txtMsg": txtMessage,"badges":b},
			function(data){
	            $("#badgeOptions").html(data);
		}, 'text');

}

function sendBadge() {
	//alert("sendBadge called")
	var b="";
	chkbox=$('input:checkbox:checked');
	for (i=0;i<chkbox.length;i++)
		b+=chkbox[i].value+' ';
	txtMessage=$("#msg").val();
		$.get("CMD", { "method" : "sendBA", "uid": $("#uid").html(),"badges":b},
			function(data){
	            $("#badgeOptions").html(data);
		}, 'text');

}


