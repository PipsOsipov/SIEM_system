from django.db import models


class SquidLog(models.Model):
    timestamp = models.DateTimeField(blank=True, null=True)
    client_ip = models.TextField(blank=True, null=True)
    status_code = models.TextField(blank=True, null=True)
    method = models.TextField(blank=True, null=True)
    url_port = models.TextField(blank=True, null=True)
    squid_user = models.TextField(blank=True, null=True)
    type = models.TextField(blank=True, null=True)
    dst_host = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'squid_log'


class SshAccessLog(models.Model):
    timestamp = models.DateTimeField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    client_ip = models.TextField(blank=True, null=True)
    user_name = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ssh_access_log'


class SshSessionLog(models.Model):
    timestamp = models.DateTimeField(blank=True, null=True)
    host_name = models.TextField(blank=True, null=True)
    session_status = models.TextField(blank=True, null=True)
    user_name = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ssh_session_log'


class UsbLog(models.Model):
    timestamp = models.DateTimeField(blank=True, null=True)
    host_name = models.TextField(blank=True, null=True)
    usb_port = models.TextField(blank=True, null=True)
    message = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'usb_log'


class VpnLog(models.Model):
    timestamp = models.DateTimeField(blank=True, null=True)
    host_name = models.TextField(blank=True, null=True)
    service = models.TextField(blank=True, null=True)
    message = models.TextField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'vpn_log'
