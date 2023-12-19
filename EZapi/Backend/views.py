from django.shortcuts import render
from django.contrib.auth import authenticate, login
from rest_framework import permissions, views, status
from rest_framework.response import Response
from dj_rest_auth.serializers import UserDetailsSerializer
from django.contrib.auth.models import User

# Replace with your JWT library imports if using a different one
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.parsers import FileUploadParser
from .serializers import OPSUserSerializer, UploadedFileSerializer


from .models import * # Replace with your actual model name
from .serializers import ClientUserSerializer, DownloadURLSerializer, UploadedFileSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.models import User
from django.utils.timezone import now
from django.utils.crypto import get_random_string
from .models import ClientUser, DownloadURL, UploadedFile
from django.core.mail import send_mail  # Import for sending emails
import datetime

class SignupView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = ClientUserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save(is_active=False)  # Create user as inactive initially
        token = get_random_string(length=32)  # Generate verification token
        user.verification_token = token  # Assign token to user
        user.save()
        try:
            send_mail(
                'Verify Your Email',
                f'Please click the link to verify your email: http://your-domain/verify-email/{token}',
                'your-email@example.com',  # Replace with your sender email
                [user.email],
                fail_silently=False,  # Raise an exception if email sending fails
            )
            return Response({'message': 'User created successfully! Please verify your email to login.'})
        except Exception as e:
            user.delete()  # Delete user if email sending fails
            return Response({'error': 'Failed to send verification email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyEmailView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = ClientUser.objects.get(verification_token=token)
            user.is_active = True
            user.verification_token = None  # Clear the token
            user.save()
            return Response({'message': 'Email verification successful! You can now login.'})
        except ClientUser.DoesNotExist:
            return Response({'error': 'Invalid verification token'}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer

class DownloadFileView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, token):
        try:
            url = DownloadURL.objects.get(token=token, is_valid=True)
        except DownloadURL.DoesNotExist:
            return Response({'error': 'Invalid download URL'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'file_url': url.uploaded_file.file.url})

class ListFilesView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        files = UploadedFile.objects.filter(uploaded_by=request.user)
        serializer = UploadedFileSerializer(files, many=True)
        return Response(serializer.data)

class GenerateDownloadURLView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, file_id):
        try:
            uploaded_file = UploadedFile.objects.get(pk=file_id, uploaded_by=request.user)
        except UploadedFile.DoesNotExist:
            return Response({'error': 'Invalid file ID'}, status=status.HTTP_404_NOT_FOUND)
        
        # Adjust expiration time as needed
        expires_at = now() + datetime.timedelta(minutes=30)
        url = DownloadURL.objects.create(uploaded_file=uploaded_file, client_user=request.user, expires_at=expires_at)
        serializer = DownloadURLSerializer(url)
        return Response(serializer.data)


class UploadFileView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [FileUploadParser]

    def post(self, request):
        if not request.user.is_staff:
            return Response({'error': 'Only Ops users can upload files'}, status=status.HTTP_403_FORBIDDEN)
        serializer = UploadedFileSerializer(data=request.FILES)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = serializer.save()

        file = request.FILES.get('file')

        if not file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        valid_extensions = ['pptx', 'docx', 'xlsx']
        if file.name.split('.')[-1] not in valid_extensions:
            return Response({'error': 'Invalid file format. Only pptx, docx, and xlsx files allowed.'}, status=status.HTTP_400_BAD_REQUEST)

        if file.size > 10485760:  # 10 MB limit
             return Response({'error': 'File size exceeds limit'}, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

        # Secure file storage and metadata creation
        uploaded_file = UploadedFile.objects.create(
            file=file,
            name=file.name,
            size=file.size,
            uploaded_by=request.user,
        )

        # Optionally encrypt the uploaded file here

        return Response({
            'id': uploaded_file.id,
            'name': uploaded_file.name,
            'uploaded_at': uploaded_file.uploaded_at,
        }, status=status.HTTP_201_CREATED)


class LoginView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({'error': 'Please provide username and password'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)

        if not user:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        login(request, user)

        # Generate JWT token for authenticated user
        token = AccessToken(api_settings.JWT_ENCODE_TOKEN, user)

        serializer = OPSUserSerializer(user)
        return Response({'token': token, 'user': serializer.data})




# Create your views here.
