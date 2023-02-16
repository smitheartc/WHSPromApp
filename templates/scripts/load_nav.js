var xhr= new XMLHttpRequest();
xhr.open('GET', '/navbar', true);
xhr.onreadystatechange= function() {
    if (this.readyState!==4) return;
    if (this.status!==200) return; // or whatever error handling you want
    // document.getElementById('navbar').innerHTML= this.responseText;
    var old_html = document.getElementsByClassName("main_container")[0].innerHTML
    document.getElementsByClassName("main_container")[0].innerHTML = this.responseText + old_html
};
xhr.send();

var xhr1= new XMLHttpRequest();
xhr1.open('GET', '/footer', true);
xhr1.onreadystatechange= function() {
    if (this.readyState!==4) return;
    if (this.status!==200) return; // or whatever error handling you want
    var old_html = document.body.innerHTML
    document.body.innerHTML = old_html + this.responseText
};
xhr1.send();
