from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from .serializer import UserSerializer,LoginSerializer,EmailCheckSerializer,ResetSerializer
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.contrib import auth
import jwt


# Create your views here.
class RegisterView(GenericAPIView):
    serializer_class=UserSerializer
    def post(self,request):
        serializer=UserSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class LoginView(GenericAPIView):
    serializer_class=LoginSerializer
    def post(self,request):
        serializer=LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)


class EmailCheckView(GenericAPIView):
    serializer_class=EmailCheckSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    
class ResetView(GenericAPIView):
    serializer_class=ResetSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        return Response(serializer.is_valid(raise_exception=True),status=status.HTTP_200_OK)
        





