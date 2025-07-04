from django.shortcuts import render
from .models import SquidLog, SshAccessLog, SshSessionLog, UsbLog, VpnLog

def all_logs(request):
    squid_logs = SquidLog.objects.order_by('-timestamp')[:50]
    ssh_access_logs = SshAccessLog.objects.order_by('-timestamp')[:50]
    ssh_session_logs = SshSessionLog.objects.order_by('-timestamp')[:50]
    usb_logs = UsbLog.objects.order_by('-timestamp')[:50]
    vpn_logs = VpnLog.objects.order_by('-timestamp')[:50]

    context = {
        'squid_logs': squid_logs,
        'ssh_access_logs': ssh_access_logs,
        'ssh_session_logs': ssh_session_logs,
        'usb_logs': usb_logs,
        'vpn_logs': vpn_logs,
    }
    return render(request, 'logs_monitoring/all_logs.html', context)