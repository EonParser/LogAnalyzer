const LogFilters = ({ detectedFields, onApplyFilters }) => {
    const [activeFilters, setActiveFilters] = React.useState({});
    const [expandedField, setExpandedField] = React.useState(null);

    React.useEffect(() => {
        // Initialize active filters when detected fields change
        const initialFilters = {};
        if (detectedFields) {
            Object.keys(detectedFields).forEach(fieldName => {
                initialFilters[fieldName] = [];
            });
        }
        setActiveFilters(initialFilters);
    }, [detectedFields]);

    const handleFilterToggle = (fieldName, value) => {
        setActiveFilters(prevFilters => {
            const updatedFilters = { ...prevFilters };
            if (!updatedFilters[fieldName]) {
                updatedFilters[fieldName] = [];
            }

            if (updatedFilters[fieldName].includes(value)) {
                // Remove value if already selected
                updatedFilters[fieldName] = updatedFilters[fieldName].filter(v => v !== value);
            } else {
                // Add value if not selected
                updatedFilters[fieldName] = [...updatedFilters[fieldName], value];
            }

            return updatedFilters;
        });
    };

    const handleApplyFilters = () => {
        // Filter out empty arrays
        const filters = {};
        Object.keys(activeFilters).forEach(key => {
            if (activeFilters[key].length > 0) {
                filters[key] = activeFilters[key];
            }
        });

        onApplyFilters(filters);
    };

    const handleResetFilters = () => {
        const resetFilters = {};
        Object.keys(activeFilters).forEach(key => {
            resetFilters[key] = [];
        });
        setActiveFilters(resetFilters);
        onApplyFilters({});  // Apply empty filters to reset
    };

    const renderFieldValues = (field) => {
        if (!field || !field.unique_values) return null;

        return React.createElement('div', { className: 'pl-4 pb-2 space-y-1' },
            field.unique_values.map((value, index) => {
                const isSelected = activeFilters[field.name] && activeFilters[field.name].includes(value);
                return React.createElement('div', { 
                    key: index,
                    className: 'flex items-center'
                }, [
                    React.createElement('input', {
                        type: 'checkbox',
                        id: `${field.name}-${index}`,
                        checked: isSelected,
                        onChange: () => handleFilterToggle(field.name, value),
                        className: 'mr-2',
                        key: 'checkbox'
                    }),
                    React.createElement('label', {
                        htmlFor: `${field.name}-${index}`,
                        className: 'text-sm text-gray-700 truncate',
                        key: 'label',
                        title: value
                    }, value)
                ]);
            })
        );
    };

    const getPriorityFields = () => {
        // Get most useful fields first
        const priorityOrder = [
            "level", "status", "method", "action", "ip", "port", 
            "user", "path", "protocol", "timestamp"
        ];

        if (!detectedFields) return [];

        // Sort fields by priority
        return Object.values(detectedFields).sort((a, b) => {
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
    };

    if (!detectedFields || Object.keys(detectedFields).length === 0) {
        return React.createElement('div', { className: 'bg-white rounded-lg shadow p-4 mb-4' }, [
            React.createElement('h3', { 
                className: 'text-lg font-semibold mb-2',
                key: 'title'
            }, 'Filters'),
            React.createElement('p', { 
                className: 'text-gray-500',
                key: 'message'
            }, 'No filterable fields detected.')
        ]);
    }

    const priorityFields = getPriorityFields();
    const hasActiveFilters = Object.values(activeFilters).some(values => values.length > 0);

    return React.createElement('div', { className: 'bg-white rounded-lg shadow p-4 mb-4' }, [
        React.createElement('div', { 
            className: 'flex justify-between items-center mb-4',
            key: 'header'
        }, [
            React.createElement('h3', { 
                className: 'text-lg font-semibold',
                key: 'title'
            }, 'Filters'),
            React.createElement('div', { 
                className: 'flex space-x-2',
                key: 'actions'
            }, [
                React.createElement('button', {
                    className: `py-1 px-3 text-sm font-medium rounded ${hasActiveFilters 
                        ? 'bg-gray-200 hover:bg-gray-300 text-gray-700' 
                        : 'bg-gray-100 text-gray-400 cursor-not-allowed'}`,
                    onClick: handleResetFilters,
                    disabled: !hasActiveFilters,
                    key: 'reset-btn'
                }, 'Reset'),
                React.createElement('button', {
                    className: `py-1 px-3 text-sm font-medium rounded ${hasActiveFilters 
                        ? 'bg-blue-600 hover:bg-blue-700 text-white' 
                        : 'bg-blue-300 text-white cursor-not-allowed'}`,
                    onClick: handleApplyFilters,
                    disabled: !hasActiveFilters,
                    key: 'apply-btn'
                }, 'Apply Filters')
            ])
        ]),

        React.createElement('div', { 
            className: 'space-y-2 max-h-80 overflow-y-auto',
            key: 'fields'
        }, priorityFields.map(field => {
            const isExpanded = expandedField === field.name;
            const hasActiveFilter = activeFilters[field.name] && activeFilters[field.name].length > 0;
            
            return React.createElement('div', { 
                key: field.name,
                className: `border rounded ${hasActiveFilter ? 'border-blue-300 bg-blue-50' : 'border-gray-200'}`
            }, [
                // Field header (always visible)
                React.createElement('div', {
                    className: 'p-2 flex justify-between items-center cursor-pointer hover:bg-gray-50',
                    onClick: () => setExpandedField(isExpanded ? null : field.name),
                    key: 'header'
                }, [
                    React.createElement('div', { className: 'flex items-center', key: 'title' }, [
                        React.createElement('span', { 
                            className: 'font-medium text-sm',
                            key: 'name'
                        }, field.standard_name !== field.name ? field.standard_name : field.name),
                        
                        hasActiveFilter && React.createElement('span', {
                            className: 'ml-2 text-xs px-2 py-0.5 bg-blue-100 text-blue-800 rounded-full',
                            key: 'count'
                        }, `${activeFilters[field.name].length} selected`)
                    ]),
                    
                    React.createElement('span', {
                        className: 'text-gray-500',
                        key: 'chevron'
                    }, isExpanded ? '▼' : '▶')
                ]),
                
                // Field values (only visible when expanded)
                isExpanded && renderFieldValues(field)
            ]);
        }))
    ]);
};