from rest_framework import serializers
from .models import OPSUser, UploadedFile
from .models import ClientUser, DownloadURL, UploadedFile
from .serializers import *
class OPSUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = OPSUser
        fields = ['username', 'email', 'groups', 'user_permissions']
        
class UploadedFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFile
        fields = ['id', 'name', 'uploaded_at', 'size', 'uploaded_by']


class ClientUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientUser
        fields = ['username', 'email']

class DownloadURLSerializer(serializers.ModelSerializer):
    uploaded_file = UploadedFileSerializer()

    class Meta:
        model = DownloadURL
        fields = ['token', 'uploaded_file', 'created_at', 'expires_at']

class UploadedFileSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = UploadedFile
        fields = ['id', 'name', 'uploaded_at', 'size', 'download_url']

    def get_download_url(self, obj):
        if not obj.pk:
            return None
        try:
            url = DownloadURL.objects.get(uploaded_file=obj, is_valid=True)
            return url.token
        except DownloadURL.DoesNotExist:
            return None