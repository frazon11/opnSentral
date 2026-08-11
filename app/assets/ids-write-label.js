(function(){
    if(location.pathname !== '/intrusion_detection.php') return;
    const note = document.querySelector('.page-title p');
    if(note){
        note.textContent = 'IDS/IPS status and centralized management across all managed OPNsense firewalls.';
    }
})();
