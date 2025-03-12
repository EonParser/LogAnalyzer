/**
 * LogAnalyzer Filters
 * Handles field-based filtering functionality
 */

// Store active filters
let activeFilters = {};

/**
 * Initializes field filters UI based on detected fields
 */
function initializeFieldFilters(fields) {
    console.log('Initializing field filters with', Object.keys(fields).length, 'fields');
    
    const filterContainer = document.getElementById('fieldFilters');
    if (!filterContainer) {
        console.error('Field filters container not found');
        return;
    }
    
    // Clear existing filters
    filterContainer.innerHTML = '';
    
    // Reset active filters
    activeFilters = {};
    
    // Priority order for fields - most useful fields first
    const priorityOrder = [
        "level", "status", "method", "action", "ip", "port", 
        "user", "path", "protocol", "timestamp"
    ];
    
    // Sort fields by priority
    const sortedFields = Object.values(fields).sort((a, b) => {
        const aPriority = priorityOrder.indexOf(a.standard_name);
        const bPriority = priorityOrder.indexOf(b.standard_name);
        
        if (aPriority === -1 && bPriority === -1) {
            // If neither are in priority list, sort by value count (fewer values first)
            return a.value_count - b.value_count;
        }
        
        if (aPriority === -1) return 1;
        if (bPriority === -1) return -1;
        
        return aPriority - bPriority;
    });
    
    // Create filter UI for each field
    sortedFields.forEach(field => {
        // Skip fields with too many values
        if (!field.unique_values || field.unique_values.length > 30) {
            return;
        }
        
        // Initialize active filters for this field
        activeFilters[field.name] = [];
        
        // Create field container
        const fieldContainer = document.createElement('div');
        fieldContainer.className = 'border border-gray-200 rounded mb-4';
        
        // Create field header
        const fieldHeader = document.createElement('div');
        fieldHeader.className = 'p-3 bg-gray-50 border-b border-gray-200 flex justify-between items-center cursor-pointer';
        fieldHeader.innerHTML = `
            <span class="font-medium">${field.standard_name !== field.name ? field.standard_name : field.name}</span>
            <svg class="w-5 h-5 text-gray-500 field-toggle" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
        `;
        
        // Create field values container (initially hidden)
        const valuesContainer = document.createElement('div');
        valuesContainer.className = 'p-3 border-t border-gray-200 hidden';
        
        // Create values list
        field.unique_values.forEach(value => {
            const valueItem = document.createElement('div');
            valueItem.className = 'flex items-center mb-2';
            
            // Create checkbox and label
            const id = `${field.name}-${value.toString().replace(/[^a-zA-Z0-9]/g, '_')}`;
            
            valueItem.innerHTML = `
                <input type="checkbox" id="${id}" data-field="${field.name}" data-value="${value}" class="field-filter-checkbox mr-2">
                <label for="${id}" class="text-sm">${value}</label>
            `;
            
            valuesContainer.appendChild(valueItem);
        });
        
        // Add everything to the field container
        fieldContainer.appendChild(fieldHeader);
        fieldContainer.appendChild(valuesContainer);
        
        // Add field container to the filters container
        filterContainer.appendChild(fieldContainer);
        
        // Toggle values visibility on header click
        fieldHeader.addEventListener('click', () => {
            const svg = fieldHeader.querySelector('svg');
            svg.classList.toggle('transform');
            svg.classList.toggle('rotate-180');
            valuesContainer.classList.toggle('hidden');
        });
    });
    
    // Add event listeners to checkboxes
    const checkboxes = document.querySelectorAll('.field-filter-checkbox');
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const field = this.dataset.field;
            const value = this.dataset.value;
            
            if (this.checked) {
                // Add value to active filters
                if (!activeFilters[field].includes(value)) {
                    activeFilters[field].push(value);
                }
            } else {
                // Remove value from active filters
                activeFilters[field] = activeFilters[field].filter(v => v !== value);
            }
        });
    });
    
    // Add event listeners to filter buttons
    setupFilterActions();
    
    console.log('Field filters initialized successfully');
}

/**
 * Sets up actions for filter buttons (reset, apply)
 */
function setupFilterActions() {
    // Reset filters button
    const resetBtn = document.getElementById('resetFilters');
    if (resetBtn) {
        resetBtn.addEventListener('click', function() {
            console.log('Resetting filters');
            
            // Uncheck all checkboxes
            const checkboxes = document.querySelectorAll('.field-filter-checkbox');
            checkboxes.forEach(checkbox => {
                checkbox.checked = false;
            });
            
            // Reset active filters
            Object.keys(activeFilters).forEach(key => {
                activeFilters[key] = [];
            });
        });
    }
    
    // Apply filters button
    const applyBtn = document.getElementById('applyFilters');
    if (applyBtn) {
        applyBtn.addEventListener('click', function() {
            console.log('Applying filters:', activeFilters);
            
            // Check if we have any active filters
            const hasActiveFilters = Object.entries(activeFilters).some(([_, values]) => values.length > 0);
            
            if (hasActiveFilters) {
                console.log('Active filters found, resubmitting form');
                
                // Use the submitForm function from main.js if available
                if (typeof submitForm === 'function') {
                    submitForm();
                } else {
                    console.warn('submitForm function not found, using form submit event');
                    
                    // Fallback to manually submitting the form
                    const form = document.querySelector('form') || document.getElementById('analyzeForm');
                    if (form) {
                        const event = new Event('submit');
                        form.dispatchEvent(event);
                    } else {
                        console.error('Form element not found');
                    }
                }
            } else {
                console.log('No active filters to apply');
            }
        });
    }
}

// Export active filters for other modules
window.activeFilters = activeFilters;