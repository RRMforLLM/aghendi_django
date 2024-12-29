from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required

from .models import Agenda, AgendaSection, AgendaElement, ElementComment
from .forms import AgendaKeyForm

from datetime import datetime, date
from calendar import monthcalendar
from collections import defaultdict

def index(request):
    return render(request, 'aghendi/index.html')

def login(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('index')
        else:
            messages.error(request, "Invalid username or password")
    return render(request, 'aghendi/login.html')

def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if password == confirm_password:
            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already exists")
            elif User.objects.filter(email=email).exists():
                messages.error(request, "Email already registered")
            else:
                User.objects.create_user(username=username, email=email, password=password)
                messages.success(request, "Account created successfully! You can log in now.")
                return redirect('login')
        else:
            messages.error(request, "Passwords do not match")
    return render(request, 'aghendi/signup.html')

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
            
            # Check if the user is the creator
            if agenda.creator == request.user:
                messages.error(request, "You cannot join an agenda you created.")
                return render(request, 'aghendi/join_agenda.html')
            
            # Check if user is already a member
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

    if request.method == 'POST' and is_creator:
        form = AgendaKeyForm(request.POST, instance=agenda)
        if form.is_valid():
            form.save()
            messages.success(request, "Agenda key updated successfully.")
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

    return render(request, 'aghendi/view_agenda.html', {
        'agenda': agenda,
        'sections': section_data,
        'is_creator': is_creator,
        'is_editor': is_editor,
        'is_member': is_member,
        'form': form,
        'user_urgent_elements': user_urgent_elements,
        'user_completed_elements': user_completed_elements,
    })

@login_required
def calendar_view(request, agenda_id):
    agenda = get_object_or_404(Agenda, id=agenda_id)
    
    # Check permissions
    is_creator = request.user == agenda.creator
    is_editor = request.user in agenda.editors.all()
    is_member = request.user in agenda.members.all()
    
    if not (is_creator or is_editor or is_member):
        messages.error(request, "You do not have permission to view this agenda's calendar.")
        return redirect('index')
    
    # Get current year and month from query parameters or use current date
    year = int(request.GET.get('year', datetime.now().year))
    month = int(request.GET.get('month', datetime.now().month))
    selected_section = request.GET.get('section', '')
    
    # Get calendar for current month
    cal = monthcalendar(year, month)
    
    # Get all elements for this agenda
    elements_query = AgendaElement.objects.filter(
        section__agenda=agenda
    ).select_related('section')
    
    # Apply section filter if specified
    if selected_section:
        elements_query = elements_query.filter(section__id=selected_section)
    
    # Create dictionaries for emission and deadline dates
    emission_dates = defaultdict(list)
    deadline_dates = defaultdict(list)
    
    # Organize elements by date
    for element in elements_query:
        if element.emission:
            emission_dates[element.emission].append({
                'id': element.id,
                'subject': element.subject,
                'section': element.section.name,
                'section_id': element.section.id,
                'type': 'emission',
                'urgent': request.user in element.urgent.all(),
                'completed': request.user in element.completed.all()
            })
        if element.deadline:
            deadline_dates[element.deadline].append({
                'id': element.id,
                'subject': element.subject,
                'section': element.section.name,
                'section_id': element.section.id,
                'type': 'deadline',
                'urgent': request.user in element.urgent.all(),
                'completed': request.user in element.completed.all()
            })
    
    # Get all sections for the filter dropdown
    sections = agenda.sections.all()
    
    # Calculate previous and next month links
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
                
                AgendaElement.objects.create(
                    section=section,
                    subject=subject,
                    details=details,
                    emission=emission,
                    deadline=deadline
                )
                messages.success(request, "Element added successfully.")
                return redirect('view_agenda', agenda_id=agenda.id)
            except ValueError:
                messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
                return redirect('add_element', agenda_id=agenda.id, section_id=section.id)
        else:
            messages.error(request, "All fields are required.")
            return redirect('add_element', agenda_id=agenda.id, section_id=section.id)
    
    return render(request, 'aghendi/add_element.html', {'section': section, 'agenda': agenda})

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
            ElementComment.objects.create(
                element=element,
                user=request.user,
                text=comment_text
            )
            messages.success(request, "Comment added successfully.")
        
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