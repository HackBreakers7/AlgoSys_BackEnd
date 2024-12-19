from django.urls import path
from .views import (
    RegisterView, VerifyOTPView, LoginView, UserProfileView, 
    UpdateUserProfileView, LogoutView, SaveQuizView, SubmitQuizView, GetQuizView, UploadStudentDetailsView, StudentDetailsView
)

urlpatterns = [
    # Registration, Login, and Profile Management Endpoints
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/VerifyOTP/', VerifyOTPView.as_view(), name='VerifyOTP'),
    path('api/login/', LoginView.as_view(), name='login'),
    
    path('api/get_user_profile/', UserProfileView.as_view(), name='get_user_profile'),
    path('api/update_user_profile/', UpdateUserProfileView.as_view(), name='update_user_profile'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/save_quiz/', SaveQuizView.as_view(), name='save_quiz'),
    path('api/submit_quiz/', SubmitQuizView.as_view(), name='submit_quiz'),
    path('api/get_quiz/', GetQuizView.as_view(), name='get_quiz'),
    path('api/upload-details/', UploadStudentDetailsView.as_view(), name='upload_student_details'),
     path('api/student-details/', StudentDetailsView.as_view(), name='student_details')
]
