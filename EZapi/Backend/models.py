from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import User
from django.db import models
from bcrypt import hashpw, gensalt
import bcrypt
from django.utils.crypto import get_random_string
from django.utils import timezone


class ClientUser(AbstractUser):
    email = models.EmailField(unique = True)
    
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='client_users',  # Specify a unique related_name
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='client_user_permissions',  # Specify a unique related_name
        blank=True,
    )

class DownloadURL(models.Model):
    def generate_random_string():
        return get_random_string()
    uploaded_file = models.ForeignKey('UploadedFile', on_delete=models.CASCADE)
    client_user = models.ForeignKey('ClientUser', on_delete=models.CASCADE)
    token = models.CharField(max_length=32, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    def is_valid(self):
        if not self.expires_at:
            return True
        return self.expires_at > timezone.now()

    def __str__(self):
        return f"Download URL for {self.uploaded_file.name} (User: {self.client_user.username})"



# Create your models here.
class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')  # Adjust upload path as needed
    name = models.CharField(max_length=255)
    size = models.PositiveIntegerField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.name} ({self.uploaded_at})"

class OPSUser(AbstractUser):
    # Your existing user fields (username, email, etc.)

    password = models.CharField(max_length=128, blank=True)

    def set_password(self, password):
        self.password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
    
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='ops_users',  
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='ops_user_permissions',  # Add a unique related_name
        blank=True,
    )
