from django.urls import path
from . import views as ticketView

urlpatterns = [
    path('', ticketView.get_all_tickets_view, name='get_all_tickets'),
    path('create/', ticketView.create_ticket, name='create_ticket'),
    path('addComment/', ticketView.add_comment_view, name='add_comment'),  # Updated URL pattern
    path('<str:ticket_id>/', ticketView.get_ticket_view, name='get_ticket'),
    path('<str:ticket_id>/update/', ticketView.update_ticket_view, name='update_ticket'),
    path('<str:ticket_id>/delete/', ticketView.delete_ticket_view, name='delete_ticket'),
]
