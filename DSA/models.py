from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta
from django.core.exceptions import ValidationError

class CustomUser(AbstractUser):
    # Full name (first name and last name can be used, or you can combine all names into one field)
    full_name = models.CharField(max_length=255)

    # Additional fields
    user_class = models.CharField(max_length=50, blank=True, null=True)  # Optional field for class of the student
    roll_no = models.CharField(max_length=20,default='default_roll_no')
    stream = models.CharField(max_length=100, blank=True)     # Optional stream
    dob = models.DateField(blank=True, null=True)                        # Allow DOB to be optional
    college_name = models.CharField(max_length=255, blank=True, null=True)  # Optional college name
    contact_number = models.CharField(max_length=15, blank=True, null=True)
    # Overriding the username and email fields from AbstractUser
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    bio = models.TextField(blank=True, null=True)  # Add 'bio'
    links = models.TextField(blank=True, null=True)  # Add 'links'
    # Override groups and user_permissions fields to resolve the conflict with related_name
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_groups',  # Change the related name
        blank=True
    )
    
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_permissions',  # Change the related name
        blank=True
    )
    def clean(self):
        super().clean()
        if self.contact_number and not self.contact_number.isdigit():
            raise ValidationError("Contact number must contain only digits.")


    def _str_(self):
        return self.username

class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    otp_verified = models.BooleanField(default=False)  # Changed for clarity
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Adding OTP expiration (5 minutes validity by default)
    expired_at = models.DateTimeField(default=timezone.now() + timedelta(minutes=5))
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'otp_code']),  # Indexing user and otp_code for faster lookups
        ]

    def is_expired(self):
        return timezone.now() > self.expired_at  # Check if OTP has expired

    def _str_(self):
        return f"OTP for {self.user.username} (Code: {self.otp_code})"
    
    from django.db import models

class Quiz(models.Model):
    
    question = models.TextField(null=True, blank=True)

    optionA = models.TextField()
    optionB = models.TextField()
    optionC = models.TextField()
    optionD = models.TextField()
    correctOption = models.CharField(max_length=1)

class UserSubmission(models.Model):
    userId = models.IntegerField()
    quizId = models.IntegerField()
    marks = models.IntegerField()
    isAttempted = models.BooleanField(default=False)

class StudentResult(models.Model):
    roll_no = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=100)
    performance = models.DecimalField(max_digits=5, decimal_places=2)  # Score out of 4
    mcqs = models.DecimalField(max_digits=5, decimal_places=2)  # Score out of 4
    attendance = models.DecimalField(max_digits=5, decimal_places=2)  # Score out of 2
    practical_no = models.PositiveIntegerField(default=0)  # Temporary default
     # Number of practicals attended
    batch = models.CharField(
        max_length=10,
        choices=[('A', 'Batch A'), ('B', 'Batch B'), ('C', 'Batch C')],
        default='A',
    )

    @property
    def total(self):
        """
        Calculate the total score out of 10:
        - Performance: max 4
        - MCQs: max 4
        - Attendance: max 2
        """
        return round(self.performance + self.mcqs + self.attendance, 2)

    def _str_(self):
        return f"{self.roll_no} - {self.name}"