from django_filters import rest_framework as filters
from .models import Task

class TaskFilter(filters.FilterSet):
    status = filters.CharFilter(lookup_expr='icontains')
    currency = filters.CharFilter(lookup_expr='icontains')
    responsible_user = filters.CharFilter(field_name='responsible_user__email', lookup_expr='iexact')
    created_by = filters.CharFilter(field_name='created_by__email', lookup_expr='iexact')

    class Meta:
        model = Task
        fields = ['status', 'currency', 'responsible_user', 'created_by']