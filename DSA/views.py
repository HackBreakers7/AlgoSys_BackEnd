from django.core.mail import send_mail
import random
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import CustomUser, OTP
from django.conf import settings
from django.db import transaction
import random
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from .models import CustomUser, OTP
import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):
    def post(self, request):
        if request.method == 'POST':

        # Extract data from the request
            username = request.data.get('username')
            full_name = request.data.get('full_name')
            user_class = request.data.get('user_class')
            roll_no = request.data.get('roll_no')
            stream = request.data.get('stream')
            email = request.data.get('email')
            contact_number = request.data.get('contact_number')
            dob = request.data.get('dob')
            password = request.data.get('password')
            college_name = request.data.get('college_name')
        

        # Validate that required fields are present
        required_fields = ['username', 'full_name', 'email', 'user_class', 
            'roll_no', 'stream', 'dob', 'college_name','contact_number',
            'password']
        for field in required_fields:
            if not request.data.get(field):
                return Response({'error': f'{field} is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the username or email already exists
        if CustomUser.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        

        # Validate dob format
        try:
            # First, try to parse it as YYYY-MM-DD
            dob = datetime.strptime(dob, '%Y-%m-%d').date()
        except ValueError:
            try:
                # If that fails, try parsing it as DD-MM-YYYY
                dob = datetime.strptime(dob, '%d-%m-%Y').date()
            except ValueError:
                return Response({'error': 'Invalid date format for dob. Use YYYY-MM-DD or DD-MM-YYYY.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate OTP
        otp_code = str(random.randint(100000, 999999))

        try:
            # Store temporary data
            user = CustomUser(
                username=username,
                full_name=full_name,
                user_class=user_class,
                roll_no=roll_no,
                stream=stream,
                email=email,
                contact_number=contact_number,
                dob=dob,
                password=password,  # Don't save yet, need to verify OTP first
                college_name=college_name
            )
            user.set_password(password)  # Hash password before saving
            user.save()  # Save user to create a reference for OTP

            # Send OTP email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp_code}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )

            # Create OTP record
            otp_instance = OTP.objects.create(
                user=user,  # Associate OTP with the newly created user
                otp_code=otp_code
            )
            # Return success response to wait for OTP verification
            return Response(
                {'message': 'User registered successfully. Please verify OTP.'},
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            print(f"Registration failed: {e}")
            return Response(
                {'error': 'Registration failed. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        print(f"Received request data: {request.data}")
        username = request.data.get('username')
        otp = request.data.get('otp_code')

        # Validate input
        if not username or not otp:
            return Response({"error": "Username and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the user and OTP record
            user = CustomUser.objects.get(username=username)  # Fetch the user
            otp_record = OTP.objects.get(otp_code=otp, user=user)  # Fetch OTP record based on OTP and user

            # Check if OTP is already verified
            if otp_record.otp_verified:
                return Response({"error": "OTP has already been verified."}, status=status.HTTP_400_BAD_REQUEST)

            # Mark OTP as verified
            otp_record.otp_verified = True
            otp_record.save()

            # Return success response
            return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid username."}, status=status.HTTP_400_BAD_REQUEST)

        except OTP.DoesNotExist:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": f"Error during OTP verification: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class LoginView(APIView): 
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        print(f"Received login attempt - Username: {username}")

        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        print(f"User found: {user.username}")

        # Check if the user is active
        if not user.is_active:
            return Response({"error": "Account is inactive. Please contact support."}, status=status.HTTP_403_FORBIDDEN)

        # Determine if the user is a superuser or normal user
        is_superuser = user.is_staff and user.is_active

        # Check password
        if user.check_password(password):
            # Generate tokens only if the user exists and the password is correct
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Include is_superuser in the access token payload
            access_token_payload = refresh.access_token.payload
            access_token_payload['is_superuser'] = is_superuser

            # Optionally store tokens in the database
            user.refresh_token = str(refresh)  # Save refresh token
            user.access_token = access_token  # Save access token
            user.save()

            return Response({
                "refresh": str(refresh),
                "access": access_token,
                "is_superuser": is_superuser,  # Include is_superuser in the response
                "message": "Login successful.",
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

class UserProfileView(APIView):
    """
    API View to fetch and return user profile details.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user  # Get the current logged-in user
        profile_data = {
            "full_name": user.full_name,
            "user_class": user.user_class,
            "roll_no": user.roll_no,
            "stream": user.stream,
            "dob": user.dob,
            "college_name": user.college_name,
            "contact_number": user.contact_number,
            "username": user.username,
            "email": user.email,
        }
        return Response(profile_data)


from django.http import JsonResponse
from django.views import View
from django.utils.dateparse import parse_date
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
import json

@method_decorator(csrf_exempt, name='dispatch')
class UpdateUserProfileView(View):
    def put(self, request):
        print("Headers:", request.headers)

        # Authenticate the user
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization token missing or invalid'}, status=401)

        token = auth_header.split(' ')[1]
        try:
            validated_token = JWTAuthentication().get_validated_token(token)
            user = JWTAuthentication().get_user(validated_token)
        except Exception as e:
            print("Authentication error:", e)
            return JsonResponse({'error': 'Invalid token'}, status=401)

        try:
            data = json.loads(request.body)

            # Update user fields
            user.full_name = data.get('full_name', user.full_name)
            user.user_class = data.get('user_class', user.user_class)
            user.roll_no = data.get('roll_no', user.roll_no)
            user.stream = data.get('stream', user.stream)
            user.college_name = data.get('college_name', user.college_name)
            user.contact_number = data.get('contact_number', user.contact_number)
            user.bio = data.get('bio', user.bio)
            user.links = data.get('links', user.links)

            # Handle 'dob'
            dob = data.get('dob')
            if dob:
                parsed_dob = parse_date(dob)
                if not parsed_dob:
                    return JsonResponse({'error': 'Invalid date format for dob.'}, status=400)
                user.dob = parsed_dob

            # Save changes
            user.save()
            return JsonResponse({'message': 'Profile updated successfully!'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            print("Error:", e)
            return JsonResponse({'error': 'Internal server error', 'details': str(e)}, status=500)
        

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logged out successfully."}, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)



from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json
import logging
from .models import Quiz, UserSubmission

# Setting up logging for debugging
logger = logging.getLogger(__name__)

# SaveQuizView class
@method_decorator(csrf_exempt, name='dispatch')  # Disable CSRF for this view
class SaveQuizView(View):
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            for q in data['questions']:
                Quiz.objects.create(
                    question=q['question'],
                    optionA=q['options']['A'],
                    optionB=q['options']['B'],
                    optionC=q['options']['C'],
                    optionD=q['options']['D'],
                    correctOption=q['correct']
                )
            return JsonResponse({"message": "Quiz saved successfully!"})
        except json.JSONDecodeError:
            logger.error("Invalid JSON data received")
            return JsonResponse({"error": "Invalid JSON data"}, status=400)
        except KeyError as e:
            logger.error(f"Missing required data: {e}")
            return JsonResponse({"error": f"Missing required data: {e}"}, status=400)
        except Exception as e:
            logger.error(f"Error occurred: {e}")
            return JsonResponse({"error": str(e)}, status=500)


# SubmitQuizView class
 # Disable CSRF for this view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .models import UserSubmission  # Your model

class SubmitQuizView(APIView):
    """
    API view to submit quiz responses.
    """

    # Apply JWT Authentication and require users to be authenticated
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @method_decorator(csrf_exempt)  # CSRF exemption (if CSRF middleware still interferes)
    def post(self, request, *args, **kwargs):
        try:
            data = request.data
            user_id = request.user.id  # Retrieve user ID from JWT token
            responses = data.get('responses', [])
            quiz_id = data['responses'][0]['questionId'] if responses else None  # Extract quiz ID

            if not quiz_id:
                return Response({"error": "No quiz data submitted"}, status=status.HTTP_400_BAD_REQUEST)

            # Check if user already attempted the quiz
            if UserSubmission.objects.filter(userId=user_id, quizId=quiz_id, isAttempted=True).exists():
                return Response({"message": "Already attempted"}, status=status.HTTP_400_BAD_REQUEST)

            # Save user submission
            marks = data.get('score', 0)  # Default score to 0 if not provided
            UserSubmission.objects.create(
                userId=user_id,
                quizId=quiz_id,
                marks=marks,
                isAttempted=True
            )
            return Response({"message": "Quiz submitted successfully!"}, status=status.HTTP_201_CREATED)
        
        except KeyError as e:
            return Response({"error": f"Missing required data: {e}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from django.http import JsonResponse
from django.views import View
from .models import Quiz  # Your Quiz model

class GetQuizView(View):
    def get(self, request, *args, **kwargs):
        try:
            # Fetch all the quiz questions
            quiz_questions = Quiz.objects.all()

            # Serialize the quiz data
            questions = [
                {
                    "id": quiz.id,
                    "question": quiz.question,
                    "options": {
                        "A": quiz.optionA,
                        "B": quiz.optionB,
                        "C": quiz.optionC,
                        "D": quiz.optionD,
                    },
                }
                for quiz in quiz_questions
            ]

            return JsonResponse({"questions": questions}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from .models import StudentResult  # Assuming this is your model

class UploadStudentDetailsView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Retrieve data from the request
            roll_no = request.data.get('roll_no')
            name = request.data.get('name')
            performance = float(request.data.get('performance', 0))  # Score out of 4
            mcqs = float(request.data.get('mcqs', 0))  # Score out of 4
            attendance = float(request.data.get('attendance', 0))  # Score out of 
            practical_no = int(request.data.get('practical_no', 0))  # Number of practicals attended
            batch = request.data.get('batch')

            # Check if all required fields are provided
            if not all([roll_no, name, mcqs, attendance, practical_no, batch]):
                return JsonResponse({'success': False, 'error': 'All fields are required.'}, status=400)

            # Create the StudentResult object
            student_result = StudentResult(
                roll_no=roll_no,
                name=name,
                performance=performance,
                mcqs=mcqs,
                attendance=attendance,
                practical_no=practical_no,
                batch=batch,
            )
            student_result.save()

            # Calculate total score (performance + mcqs + attendance)
            total_score = round(student_result.performance + student_result.mcqs + student_result.attendance , 2)

            # Return a success response with the total score
            return JsonResponse({
                'success': True,
                'message': 'Student details uploaded successfully.',
                'total_score': total_score,  # Total out of 10
                'practical_no': practical_no,  # Number of practicals attended
            })

        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)

from django.http import JsonResponse
from django.views import View
from .models import StudentResult  # Ensure the correct model is imported

class StudentDetailsView(View):
    def get(self, request):
        # Fetch all students from the database
        students = StudentResult.objects.all().values(
            'roll_no', 'name', 'performance', 'mcqs', 'attendance', 'practical_no', 'batch'
        )
        # Return the data as JSON
        return JsonResponse({'students': list(students)}, safe=False)