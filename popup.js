chrome.storage.local.get('html', function(data) {
    document.getElementById('output').innerHTML = data.html;
  });


function clean(){
    document.getElementById('output').innerHTML = '';
    chrome.storage.local.set({ html: '' }, function () {
        console.log('html is cleaned');
    });
    chrome.runtime.sendMessage({cleanup: "all"}, function(response) {
        console.log(response.farewell);
      });
}
window.onload = function() {
    document.getElementById('cleanButton').onclick = clean;
}
