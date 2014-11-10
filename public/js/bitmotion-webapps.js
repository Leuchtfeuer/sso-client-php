/**
 * Created by svengahle on 28.08.14.
 */
$(document).ready(function(){

    $('#directlogin').on('click',function(){
        form.submit();
    });

    $('#ssologon').on('click',function(){
        location.href='http://lemken-sso-dev.w1.bitmotion.de/special-pages/customer-login/?tx-lemkensso-pi1[tpaid]=ssoclient&logintype=login';
        return false;
    });

});
