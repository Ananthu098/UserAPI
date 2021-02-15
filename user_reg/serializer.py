from rest_framework import serializers 
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator



class UserSerializer(serializers.ModelSerializer):
    password=serializers.CharField(max_length=16,min_length=8,write_only=True)
    email=serializers.EmailField(max_length=100,min_length=4)
    first_name=serializers.CharField(max_length=25,min_length=2)
    last_name=serializers.CharField(max_length=25,min_length=2)

    class Meta:
        model=User
        fields=['username','first_name','last_name','email','password']

    def validate(self,attrs):
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({'email',('email already in use')})
        return super().validate(attrs)

    def create(self,validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=100, min_length=6)
    password=serializers.CharField(max_length=60,min_length=6,write_only='True')
    username=serializers.CharField(max_length=60,min_length=3,read_only='True')
    tokens=serializers.CharField(max_length=555,min_length=6,read_only='True')

    class Meta:
        model=User
        fields=['email','password','username','tokens']

 
    def validate(self,attrs):
          

        user=auth.authenticate(email=attrs['email'],password=attrs['password'])
        print(user)

        if user is None:
            raise AuthenticationFailed("invalid credentials,try again1")

        tokens={'refresh':str(RefreshToken.for_user(user)),'access':str(RefreshToken.for_user(user).access_token) }
        
    
        return {
            'email':user.email,
            'username':user.username,
            'tokens':tokens
        }
        return super().validate(attrs)



class EmailCheckSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=100, min_length=6,write_only=True)
    id=serializers.IntegerField(read_only=True)
    tokens=serializers.CharField(max_length=555,min_length=6,read_only=True)

    class Meta:
        model=User
        fields=['email','tokens','id']
    def validate(self,attrs):
        try:
            user=User.objects.get(email=attrs['email'])
            if user is None:
                raise AuthenticationFailed("invalid credentials")
            tokens=PasswordResetTokenGenerator().make_token(user)
            return {
                'id':user.id,
                'tokens':tokens
            }
        except Exception as e:
            raise AuthenticationFailed('invalid credentils', 401)

        
        return super().validate(attrs)

class ResetSerializer(serializers.ModelSerializer):
    id=serializers.IntegerField(write_only=True)
    tokens=serializers.CharField(max_length=555,min_length=6,write_only=True)
    password=serializers.CharField(max_length=16,min_length=8,write_only=True)

    class Meta:
        model=User
        fields=['tokens','id','password']

    def validate(self,attrs):
        try:
            user=User.objects.get(id=attrs['id'])
            if PasswordResetTokenGenerator().check_token(user,attrs['tokens']):
                user.set_password(attrs['password'])
                user.save()
                return "Password reset Successfull"
            else:
                raise AuthenticationFailed("token expired!", 401)
            
             
        except Exception as e:
            raise AuthenticationFailed('invalid credentils1', 401)
               
        return super().validate(attrs)

    












