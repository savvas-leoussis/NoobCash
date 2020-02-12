function fill_table(){
  var $table = $('#table');
  $(function () {
    $('#table').bootstrapTable({
     url: '/transactions/get',
     method: 'get',
     search: true
  });
  });
}

function get_html(link){
  var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
      if (this.readyState == 4 && this.status == 200) {
        document.getElementById("body").innerHTML = this.responseText;
        var parser = new DOMParser();
        var htmlDoc = parser.parseFromString(this.responseText,"text/html");
        var title = htmlDoc.getElementsByTagName("title");
        document.title = title[0].textContent;
        if (link=="/view_transactions"){
          fill_table();
        }
        else if (link=="/view_balance"){
          get_balance();
        }
      }
    };
    xhttp.open("GET", link, true);
    xhttp.send();
}

function submit_transaction(){
  var recipient_id = document.getElementById('recipient_id').value;
  var amount = document.getElementById('amount').value;
  console.log(recipient_id);
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {

    }
  };
  xhttp.open("POST", '/make_new_transaction', true);
  xhttp.setRequestHeader('Content-type', 'application/javascript');
  xhttp.send(JSON.stringify({'recipient_id': recipient_id, 'amount': amount}));
}

function get_balance(){
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      document.getElementById("balance").innerHTML = JSON.parse(this.responseText)['1000'];
    }
  };
  xhttp.open("GET", "/balance/get", true);
  xhttp.send();
}
