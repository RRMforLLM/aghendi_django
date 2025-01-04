from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.core.mail import send_mail, send_mass_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth import authenticate, login as auth_login, logout, get_user_model
from django.core.cache import cache
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings

from datetime import datetime, date
from calendar import monthcalendar
from collections import defaultdict

from .models import Agenda, AgendaSection, AgendaElement, ElementComment
from .forms import AgendaKeyForm

def index(request):
    return render(request, 'aghendi/index.html')

def send_login_notification(user):
    subject = 'New Login to Your Account'
    message = f"""
    Hello {user.username},
    
    We detected a new login to your account on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.
    
    If this wasn't you, please contact support immediately.
    
    Best regards,
    Aghendi Team
    """
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=True,
    )

def send_welcome_email(user):
    subject = 'Welcome to Our Platform!'
    message = f"""
    Hello {user.username},
    
    Thank you for creating an account with us! We're excited to have you on board.
    
    You can now log in and start using our platform.
    
    Best regards,
    Aghendi Team
    """
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=True,
    )

def get_client_ip(request):
    """Get the client's IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_rate_limit_key(request, username):
    """
    Generate a rate limit key based on multiple factors to prevent blocking legitimate users
    while maintaining security
    """
    client_ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    if username:
        return f"login_attempts_user_{username}_{client_ip}"
    
    return f"login_attempts_ip_{client_ip}"

def login(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        
        username_key = get_rate_limit_key(request, username)
        ip_key = get_rate_limit_key(request, None)
        
        username_attempts = cache.get(username_key, 0)
        if username_attempts >= 5:
            lockout_duration = 15 * 60
            if not cache.get(f"lockout_{username_key}"):
                cache.set(f"lockout_{username_key}", True, timeout=lockout_duration)
            
            minutes_left = round(cache.ttl(f"lockout_{username_key}") / 60)
            messages.error(
                request,
                f"Too many failed attempts for this username. Please try again in {minutes_left} minutes."
            )
            return render(request, 'aghendi/login.html', {'show_reset': True})
        
        ip_attempts = cache.get(ip_key, 0)
        if ip_attempts >= 20:
            lockout_duration = 30 * 60
            if not cache.get(f"lockout_{ip_key}"):
                cache.set(f"lockout_{ip_key}", True, timeout=lockout_duration)
            
            minutes_left = round(cache.ttl(f"lockout_{ip_key}") / 60)
            messages.error(
                request,
                f"Too many login attempts from this location. Please try again in {minutes_left} minutes."
            )
            return render(request, 'aghendi/login.html', {'show_reset': True})
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            auth_login(request, user)
            cache.delete(username_key)
            cache.delete(ip_key)
            cache.delete(f"lockout_{username_key}")
            cache.delete(f"lockout_{ip_key}")
            
            if 'failed_login' in request.session:
                del request.session['failed_login']
            
            send_login_notification(user)
            
            return redirect('index')
        else:
            cache.set(username_key, username_attempts + 1, timeout=24*60*60)
            cache.set(ip_key, ip_attempts + 1, timeout=24*60*60)
            
            remaining_username_attempts = 5 - username_attempts - 1
            if remaining_username_attempts > 0:
                messages.error(
                    request,
                    f"Invalid credentials. {remaining_username_attempts} attempts remaining for this username."
                )
            else:
                messages.error(request, "Invalid username or password")
            
            request.session['failed_login'] = True
            
    show_reset = request.session.get('failed_login', False)
    return render(request, 'aghendi/login.html', {'show_reset': show_reset})

def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        client_ip = get_client_ip(request)
        signup_key = f"signup_attempts_{client_ip}"
        
        signup_attempts = cache.get(signup_key, 0)
        if signup_attempts >= 10:
            messages.error(request, "Too many signup attempts. Please try again in 1 hour.")
            return render(request, 'aghendi/signup.html')
        
        cache.set(signup_key, signup_attempts + 1, timeout=60*60)
        
        if password == confirm_password:
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists")
            elif User.objects.filter(email=email).exists():
                messages.error(request, "Email already registered")
            else:
                user = User.objects.create_user(username=username, email=email, password=password)
                messages.success(request, "Account created successfully! You can log in now.")
                
                send_welcome_email(user)
                
                return redirect('login')
        else:
            messages.error(request, "Passwords do not match")
            
    return render(request, 'aghendi/signup.html')

def password_reset_request(request):
    if request.method == "POST":
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            reset_url = request.build_absolute_uri(
                reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            )
            
            send_mail(
                'Password Reset Request',
                f'Please click the following link to reset your password: {reset_url}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            messages.success(request, "Password reset instructions have been sent to your email.")
        except User.DoesNotExist:
            messages.success(request, "If an account exists with this email, password reset instructions will be sent.")
        
    return render(request, 'aghendi/password_reset_request.html')

def password_reset_confirm(request, uidb64, token):
    try:
        # Decode the user id
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
        
        # Check if token is valid
        if default_token_generator.check_token(user, token):
            if request.method == 'POST':
                # Get passwords from the form
                new_password1 = request.POST.get('new_password1')
                new_password2 = request.POST.get('new_password2')
                
                # Verify passwords match
                if new_password1 == new_password2:
                    # Set the new password
                    user.set_password(new_password1)
                    user.save()
                    messages.success(request, 'Your password has been successfully changed.')
                    return redirect('login')
                else:
                    messages.error(request, 'Passwords do not match.')
            
            return render(request, 'aghendi/password_reset_confirm.html', {
                'validlink': True
            })
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        user = None
    
    return render(request, 'aghendi/password_reset_confirm.html', {
        'validlink': False
    })

def logout_view(request):
    logout(request)
    return redirect('index')

@login_required
def create_agenda(request):
    if request.method == "POST":
        name = request.POST.get('name')
        key = request.POST.get('key')
        confirm_key = request.POST.get('confirm_key')

        if not name or not key or not confirm_key:
            messages.error(request, "All fields are required.")
            return render(request, 'aghendi/create_agenda.html')

        if key != confirm_key:
            messages.error(request, "Keys do not match.")
            return render(request, 'aghendi/create_agenda.html')

        if Agenda.objects.filter(name=name).exists():
            messages.error(request, "An agenda with this name already exists.")
            return render(request, 'aghendi/create_agenda.html')

        agenda = Agenda.objects.create(
            name=name,
            key=key,
            creator=request.user
        )

        messages.success(request, f"Agenda '{name}' created successfully!")
        return redirect('index')

    return render(request, 'aghendi/create_agenda.html')

@login_required
def join_agenda(request):
    if request.method == "POST":
        name = request.POST.get('agenda_name')
        print(f"Submitted agenda name: {name}")
        key = request.POST.get('agenda_key')
        
        try:
            agenda = Agenda.objects.get(name=name)
            
            if agenda.creator == request.user:
                messages.error(request, "You cannot join an agenda you created.")
                return render(request, 'aghendi/join_agenda.html')
            
            if request.user in agenda.members.all():
                messages.error(request, "You are already a member of this agenda.")
                return render(request, 'aghendi/join_agenda.html')
            
            if agenda.key == key:
                agenda.members.add(request.user)
                messages.success(request, "Successfully joined the agenda!")
                return redirect('index')
            else:
                messages.error(request, "Incorrect agenda key.")
                return render(request, 'aghendi/join_agenda.html')
                
        except Agenda.DoesNotExist:
            messages.error(request, "Agenda does not exist.")
            return render(request, 'aghendi/join_agenda.html')
    
    return render(request, 'aghendi/join_agenda.html')

@login_required
def view_agenda(request, agenda_id):
    agenda = get_object_or_404(Agenda, id=agenda_id)
    is_creator = request.user == agenda.creator
    is_editor = request.user in agenda.editors.all()
    is_member = request.user in agenda.members.all()

    if not (is_creator or is_editor or is_member):
        messages.error(request, "You do not have permission to view this agenda.")
        return redirect('index')

    show_key = is_creator or (agenda.key_visible and (is_editor or is_member))

    if request.method == 'POST' and is_creator:
        form = AgendaKeyForm(request.POST, instance=agenda)
        if form.is_valid():
            form.save()
            messages.success(request, "Agenda settings updated successfully.")
            return redirect('view_agenda', agenda_id=agenda.id)
    else:
        form = AgendaKeyForm(instance=agenda)

    user_urgent_elements = AgendaElement.objects.filter(
        section__agenda=agenda,
        urgent=request.user
    ).order_by('deadline')

    user_completed_elements = AgendaElement.objects.filter(
        section__agenda=agenda,
        completed=request.user
    ).order_by('-deadline')

    sections = agenda.sections.all()
    section_data = []

    for section in sections:
        elements = section.elements.all()
        section_data.append({
            'section': section,
            'elements': elements,
            'comment_count': sum([element.comments.count() for element in elements])
        })

    context = {
        'agenda': agenda,
        'sections': section_data,
        'is_creator': is_creator,
        'is_editor': is_editor,
        'is_member': is_member,
        'form': form,
        'show_key': show_key,
        'user_urgent_elements': user_urgent_elements,
        'user_completed_elements': user_completed_elements,
    }
    return render(request, 'aghendi/view_agenda.html', context)

@login_required
def calendar_view(request, agenda_id):
    agenda = get_object_or_404(Agenda, id=agenda_id)
    
    is_creator = request.user == agenda.creator
    is_editor = request.user in agenda.editors.all()
    is_member = request.user in agenda.members.all()
    
    if not (is_creator or is_editor or is_member):
        messages.error(request, "You do not have permission to view this agenda's calendar.")
        return redirect('index')
    
    year = int(request.GET.get('year', datetime.now().year))
    month = int(request.GET.get('month', datetime.now().month))
    selected_section = request.GET.get('section', '')
    
    cal = monthcalendar(year, month)
    
    elements_query = AgendaElement.objects.filter(
        section__agenda=agenda
    ).select_related('section')
    
    if selected_section:
        elements_query = elements_query.filter(section__id=selected_section)
    
    emission_dates = defaultdict(list)
    deadline_dates = defaultdict(list)
    
    for element in elements_query:
        if element.emission:
            emission_date = element.emission.strftime('%Y-%m-%d')
            print(f"Adding emission date: {emission_date} for element: {element.subject}")
            emission_dates[emission_date].append({
                'id': element.id,
                'subject': element.subject,
                'section': element.section.name,
                'section_id': element.section.id,
                'type': 'emission',
                'urgent': request.user in element.urgent.all(),
                'completed': request.user in element.completed.all()
            })
        if element.deadline:
            deadline_date = element.deadline.strftime('%Y-%m-%d')
            print(f"Adding deadline date: {deadline_date} for element: {element.subject}")
            deadline_dates[deadline_date].append({
                'id': element.id,
                'subject': element.subject,
                'section': element.section.name,
                'section_id': element.section.id,
                'type': 'deadline',
                'urgent': request.user in element.urgent.all(),
                'completed': request.user in element.completed.all()
            })
    
    sections = agenda.sections.all()
    
    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1
    
    context = {
        'agenda': agenda,
        'calendar': cal,
        'year': year,
        'month': month,
        'month_name': date(year, month, 1).strftime('%B'),
        'emission_dates': dict(emission_dates),
        'deadline_dates': dict(deadline_dates),
        'sections': sections,
        'selected_section': selected_section,
        'prev_month': prev_month,
        'prev_year': prev_year,
        'next_month': next_month,
        'next_year': next_year,
        'is_creator': is_creator,
        'is_editor': is_editor,
        'is_member': is_member
    }
    
    return render(request, 'aghendi/calendar_view.html', context)

@login_required
def delete_agenda(request, agenda_id):
    agenda = get_object_or_404(Agenda, id=agenda_id, creator=request.user)
    
    if request.method == 'POST':
        agenda.delete()
        messages.success(request, f"Agenda '{agenda.name}' has been deleted.")
        return redirect('index')
    
    return render(request, 'aghendi/delete_agenda.html', {'agenda': agenda})

@login_required
def add_editor(request, agenda_id):
    agenda = get_object_or_404(Agenda, id=agenda_id, creator=request.user)
    
    if request.method == 'POST':
        username = request.POST.get('username')
        try:
            user_to_add = User.objects.get(username=username)
            
            if user_to_add not in agenda.members.all():
                messages.error(request, "User must be a member of the agenda first.")
                return redirect('view_agenda', agenda_id=agenda.id)
            
            agenda.editors.add(user_to_add)
            messages.success(request, f"{username} has been added as an editor.")
        except User.DoesNotExist:
            messages.error(request, "User not found.")
        
        return redirect('view_agenda', agenda_id=agenda.id)
    
    return render(request, 'aghendi/add_editor.html', {'agenda': agenda})

@login_required
def remove_editor(request, agenda_id, user_id):
    agenda = get_object_or_404(Agenda, id=agenda_id, creator=request.user)
    user_to_remove = get_object_or_404(User, id=user_id)
    
    agenda.editors.remove(user_to_remove)
    messages.success(request, f"{user_to_remove.username} has been removed as an editor.")
    return redirect('view_agenda', agenda_id=agenda.id)

@login_required
def remove_member(request, agenda_id, user_id):
    agenda = get_object_or_404(Agenda, id=agenda_id, creator=request.user)
    user_to_remove = get_object_or_404(User, id=user_id)
    
    if user_to_remove == agenda.creator:
        messages.error(request, "Cannot remove the creator of the agenda.")
        return redirect('view_agenda', agenda_id=agenda.id)
    
    if user_to_remove not in agenda.members.all():
        messages.error(request, f"{user_to_remove.username} is not a member of this agenda.")
        return redirect('view_agenda', agenda_id=agenda.id)
    
    try:
        if user_to_remove in agenda.editors.all():
            agenda.editors.remove(user_to_remove)
        
        agenda.members.remove(user_to_remove)
        
        for element in AgendaElement.objects.filter(section__agenda=agenda):
            element.urgent.remove(user_to_remove)
            element.completed.remove(user_to_remove)
            element.nothing.remove(user_to_remove)
        
        agenda.save()
        
        messages.success(request, f"{user_to_remove.username} has been removed from the agenda.")
        
    except Exception as e:
        messages.error(request, f"Error removing member: {str(e)}")
        
    return redirect('view_agenda', agenda_id=agenda.id)

@login_required
def leave_agenda(request, agenda_id):
    agenda = get_object_or_404(Agenda, id=agenda_id)
    
    if request.user not in agenda.members.all():
        messages.error(request, "You are not a member of this agenda.")
        return redirect('index')
    
    if request.user == agenda.creator:
        messages.error(request, "As the creator, you cannot leave your own agenda.")
        return redirect('view_agenda', agenda_id=agenda.id)
    
    if request.method == 'POST':
        try:
            if request.user in agenda.editors.all():
                agenda.editors.remove(request.user)
            
            agenda.members.remove(request.user)
            
            for element in AgendaElement.objects.filter(section__agenda=agenda):
                element.urgent.remove(request.user)
                element.completed.remove(request.user)
                element.nothing.remove(request.user)
            
            agenda.save()
            
            messages.success(request, f"You have successfully left the agenda '{agenda.name}'.")
            return redirect('index')
        
        except Exception as e:
            messages.error(request, f"Error leaving agenda: {str(e)}")
            return redirect('view_agenda', agenda_id=agenda.id)
    
    return render(request, 'aghendi/leave_agenda.html', {'agenda': agenda})

@login_required
def create_section(request, agenda_id):
    try:
        agenda = get_object_or_404(Agenda, id=agenda_id)
        
        if request.user != agenda.creator and request.user not in agenda.editors.all():
            messages.error(request, "You do not have permission to create sections.")
            return redirect('view_agenda', agenda_id=agenda.id)
        
        if request.method == 'POST':
            section_name = request.POST.get('section_name')
            if section_name:
                AgendaSection.objects.create(
                    name=section_name,
                    agenda=agenda
                )
                messages.success(request, f"Section '{section_name}' created successfully.")
            return redirect('view_agenda', agenda_id=agenda.id)
        
        return redirect('view_agenda', agenda_id=agenda.id)
    
    except Exception as e:
        print(f"Error in create_section: {e}")
        messages.error(request, "An error occurred while creating the section.")
        return redirect('index')

@login_required
def delete_section(request, agenda_id, section_id):
    agenda = get_object_or_404(Agenda, id=agenda_id)
    section = get_object_or_404(AgendaSection, id=section_id, agenda=agenda)

    if request.user != agenda.creator and request.user not in agenda.editors.all():
        messages.error(request, "You do not have permission to delete this section.")
        return redirect('view_agenda', agenda_id=agenda.id)

    if request.method == 'POST':
        section.delete()
        messages.success(request, f"Section '{section.name}' has been deleted.")
        return redirect('view_agenda', agenda_id=agenda.id)

    return render(request, 'aghendi/delete_section.html', {'section': section, 'agenda': agenda})

def send_element_notification_emails(agenda, element, request, is_edit=False):
    recipient_emails = set()
    
    if agenda.creator.email:
        recipient_emails.add(agenda.creator.email)
    
    for editor in agenda.editors.all():
        if editor.email:
            recipient_emails.add(editor.email)
    
    for member in agenda.members.all():
        if member.email:
            recipient_emails.add(member.email)
    
    action = "edited" if is_edit else "added"
    subject = f"Element {action} in {agenda.name}: {element.subject}"
    message = f"""
An element has been {action} in the agenda "{agenda.name}":

Section: {element.section.name}
Subject: {element.subject}
Details: {element.details}
Emission: {element.emission}
Deadline: {element.deadline}

View the element at: {request.build_absolute_uri(
    reverse('element_detail', kwargs={
        'agenda_id': agenda.id,
        'section_id': element.section.id,
        'element_id': element.id
    })
)}
"""
    
    datatuple = (
        (subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        for email in recipient_emails
    )
    
    try:
        send_mass_mail(datatuple, fail_silently=False)
        return len(recipient_emails)
    except Exception as e:
        print(f"Error sending notification emails: {e}")
        return 0

@login_required
def add_element(request, agenda_id, section_id):
    agenda = get_object_or_404(Agenda, id=agenda_id)
    section = get_object_or_404(AgendaSection, id=section_id, agenda=agenda)
    
    if request.method == 'POST':
        subject = request.POST.get('subject')
        details = request.POST.get('details')
        emission = request.POST.get('emission')
        deadline = request.POST.get('deadline')
        
        if subject and details and emission and deadline:
            try:
                emission_date = datetime.strptime(emission, '%Y-%m-%d')
                deadline_date = datetime.strptime(deadline, '%Y-%m-%d')
                
                if emission_date > deadline_date:
                    messages.error(request, "Emission date cannot be after the deadline.")
                    return redirect('add_element', agenda_id=agenda.id, section_id=section.id)
                
                element = AgendaElement.objects.create(
                    section=section,
                    subject=subject,
                    details=details,
                    emission=emission,
                    deadline=deadline
                )
                
                emails_sent = send_element_notification_emails(agenda, element, request)
                
                if emails_sent > 0:
                    messages.success(request, f"Element added successfully. Notification sent to {emails_sent} recipients.")
                else:
                    messages.success(request, "Element added successfully.")
                    messages.warning(request, "Could not send notification emails.")
                
                return redirect('view_agenda', agenda_id=agenda.id)
            except ValueError:
                messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
                return redirect('add_element', agenda_id=agenda.id, section_id=section.id)
        else:
            messages.error(request, "All fields are required.")
            return redirect('add_element', agenda_id=agenda.id, section_id=section.id)
    
    return render(request, 'aghendi/add_element.html', {'section': section, 'agenda': agenda})

@login_required
def edit_element(request, agenda_id, section_id, element_id):
    element = get_object_or_404(AgendaElement, id=element_id)
    agenda = element.section.agenda

    if request.user != agenda.creator and request.user not in agenda.editors.all():
        messages.error(request, "You do not have permission to edit this element.")
        return redirect('element_detail', agenda_id=agenda_id, section_id=section_id, element_id=element_id)

    if request.method == 'POST':
        subject = request.POST.get('subject')
        details = request.POST.get('details')
        emission = request.POST.get('emission')
        deadline = request.POST.get('deadline')

        if subject and details and emission and deadline:
            try:
                emission_date = datetime.strptime(emission, '%Y-%m-%d')
                deadline_date = datetime.strptime(deadline, '%Y-%m-%d')

                if emission_date > deadline_date:
                    messages.error(request, "Emission date cannot be after the deadline.")
                    return redirect('edit_element', agenda_id=agenda_id, section_id=section_id, element_id=element_id)

                element.subject = subject
                element.details = details
                element.emission = emission
                element.deadline = deadline
                element.save()

                emails_sent = send_element_notification_emails(agenda, element, request, is_edit=True)
                
                if emails_sent > 0:
                    messages.success(request, f"Element updated successfully. Notification sent to {emails_sent} recipients.")
                else:
                    messages.success(request, "Element updated successfully.")
                    messages.warning(request, "Could not send notification emails.")

                return redirect('element_detail', agenda_id=agenda_id, section_id=section_id, element_id=element_id)
            except ValueError:
                messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
        else:
            messages.error(request, "All fields are required.")

    return render(request, 'aghendi/edit_element.html', {
        'element': element,
        'agenda': agenda,
        'section': element.section
    })

@login_required
def element_detail(request, agenda_id, section_id, element_id):
    element = get_object_or_404(AgendaElement, id=element_id)
    agenda = element.section.agenda
    section = element.section

    is_creator = request.user == agenda.creator
    is_editor = request.user in agenda.editors.all()
    is_member = request.user in agenda.members.all()

    if not (is_creator or is_editor or is_member):
        messages.error(request, "You do not have permission to view this element.")
        return redirect('index')

    comments = element.comments.all().order_by('-created_at')

    return render(request, 'aghendi/element_detail.html', {
        'element': element,
        'agenda': agenda,
        'section': section,
        'comments': comments,
        'is_creator': is_creator,
        'is_editor': is_editor,
        'is_member': is_member
    })

@login_required
def flag_element(request, agenda_id, section_id, element_id):
    element = get_object_or_404(AgendaElement, id=element_id)
    agenda = element.section.agenda
    
    if not (request.user == agenda.creator or 
            request.user in agenda.editors.all() or 
            request.user in agenda.members.all()):
        messages.error(request, "You do not have permission to flag this element.")
        return redirect('index')
    
    if request.method == 'POST':
        flag_type = request.POST.get('flag_type')
        action = request.POST.get('action')
        
        if flag_type == 'urgent':
            if action == 'add':
                element.urgent.add(request.user)
                messages.success(request, "Element marked as urgent.")
            else:
                element.urgent.remove(request.user)
                element.nothing.add(request.user)
                messages.success(request, "Urgent flag removed.")
                
        elif flag_type == 'completed':
            if action == 'add':
                element.completed.add(request.user)
                messages.success(request, "Element marked as completed.")
            else:
                element.completed.remove(request.user)
                element.nothing.add(request.user)
                messages.success(request, "Completed flag removed.")
    
    return redirect('element_detail', agenda_id=agenda_id, section_id=section_id, element_id=element_id)

@login_required
def delete_element(request, agenda_id, section_id, element_id):
    element = get_object_or_404(AgendaElement, 
        id=element_id, 
        section__agenda__creator=request.user
    )
    agenda = element.section.agenda

    if request.user != agenda.creator and request.user not in agenda.editors.all():
        messages.error(request, "You do not have permission to delete this element.")
        return redirect('view_agenda', agenda_id=agenda.id)

    if request.method == 'POST':
        agenda_id = element.section.agenda.id

        element.delete()
        messages.success(request, f"Element '{element.subject}' has been deleted.")
        return redirect('view_agenda', agenda_id=agenda_id)

    return render(request, 'aghendi/delete_element.html', {'element': element})

def send_comment_notification_emails(agenda, element, comment, request):
    recipient_emails = set()
    
    if agenda.creator.email:
        recipient_emails.add(agenda.creator.email)
    
    for editor in agenda.editors.all():
        if editor.email:
            recipient_emails.add(editor.email)
    
    for member in agenda.members.all():
        if member.email:
            recipient_emails.add(member.email)
    
    if comment.user.email in recipient_emails:
        recipient_emails.remove(comment.user.email)
    
    subject = f"New comment on element in {agenda.name}: {element.subject}"
    message = f"""
A new comment has been added to an element in the agenda "{agenda.name}":

Element: {element.subject}
Section: {element.section.name}
Author: {comment.user.username}
Comment: {comment.text}

View the element and all comments at: {request.build_absolute_uri(
    reverse('element_detail', kwargs={
        'agenda_id': agenda.id,
        'section_id': element.section.id,
        'element_id': element.id
    })
)}
"""
    
    datatuple = (
        (subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        for email in recipient_emails
    )
    
    try:
        send_mass_mail(datatuple, fail_silently=False)
        return len(recipient_emails)
    except Exception as e:
        print(f"Error sending comment notification emails: {e}")
        return 0

@login_required
def element_comments(request, agenda_id, section_id, element_id):
    element = get_object_or_404(AgendaElement, id=element_id)
    
    agenda = element.section.agenda
    section = element.section
    
    is_member = request.user in agenda.members.all()
    is_creator = request.user == agenda.creator
    is_editor = request.user in agenda.editors.all()
    
    if not (is_member or is_creator or is_editor):
        messages.error(request, "You do not have permission to comment on this element.")
        return redirect('index')
    
    if request.method == 'POST':
        comment_text = request.POST.get('comment')
        if comment_text and comment_text.strip():
            comment = ElementComment.objects.create(
                element=element,
                user=request.user,
                text=comment_text
            )
            
            emails_sent = send_comment_notification_emails(agenda, element, comment, request)
            
            if emails_sent > 0:
                messages.success(request, f"Comment added successfully. Notification sent to {emails_sent} recipients.")
            else:
                messages.success(request, "Comment added successfully.")
                messages.warning(request, "Could not send notification emails.")
        
        return redirect('element_detail', agenda_id=agenda_id, section_id=section_id, element_id=element_id)
    
    return redirect('element_detail', agenda_id=agenda_id, section_id=section_id, element_id=element_id)

@login_required
def delete_comment(request, agenda_id, section_id, element_id, comment_id):
    comment = get_object_or_404(ElementComment, id=comment_id)
    element = comment.element
    agenda = element.section.agenda
    
    if request.user != agenda.creator and request.user not in agenda.editors.all():
        messages.error(request, "You do not have permission to delete comments.")
        return redirect('element_detail', agenda_id=agenda_id, section_id=section_id, element_id=element_id)
    
    if request.method == 'POST':
        comment.delete()
        messages.success(request, "Comment deleted successfully.")
        
    return redirect('element_detail', agenda_id=agenda_id, section_id=section_id, element_id=element_id)