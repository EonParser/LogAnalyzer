/**
 * LogAnalyzer Main Application
 * Handles core application functionality and form submission
 */

// Global variables
let activeFilters = {};
let detectedFields = {};
let currentResults = null;

// Parser options based on log type
const parserOptions = {
    'standard': [
        { value: '', text: 'Auto-detect' },
        { value: 'apache_access', text: 'Apache Access Log' },
        { value: 'apache_error', text: 'Apache Error Log' },
        { value: 'nginx_access', text: 'Nginx Access Log' },
        { value: 'nginx_error', text: 'Nginx Error Log' },
        { value: 'syslog', text: 'Syslog' }
    ],
    'firewall': [
        { value: '', text: 'Auto-detect Firewall' },
        { value: 'iptables', text: 'IPTables' },
        { value: 'pfsense', text: 'pfSense' },
        { value: 'cisco_asa', text: 'Cisco ASA' },
        { value: 'windows_firewall', text: 'Windows Firewall' }
    ]
};

/**
 * Updates parser options when log type changes
 */
function updateParserOptions(logType) {
    console.log(`Updating parser options for log type: ${logType}`);
    const parserSelect = document.getElementById('parser');
    if (!parserSelect) {
        console.warn('Parser select element not found');
        return;
    }
    
    // Clear existing options
    parserSelect.innerHTML = '';
    
    // Get appropriate options based on log type
    const options = parserOptions[logType] || parserOptions['standard'];
    
    // Add options to select
    options.forEach(option => {
        const optionElement = document.createElement('option');
        optionElement.value = option.value;
        optionElement.textContent = option.text;
        parserSelect.appendChild(optionElement);
    });
    
    console.log(`Added ${options.length} parser options`);
}

/**
 * Shows error message in the UI
 */
function showError(message, resultDiv) {
    console.error(`Error: ${message}`);
    
    if (!resultDiv) {
        resultDiv = document.getElementById('results');
        if (!resultDiv) {
            resultDiv = document.createElement('div');
            resultDiv.id = 'results';
            document.querySelector('main').appendChild(resultDiv);
        }
    }
    
    resultDiv.innerHTML = `
        <div class="bg-red-50 border border-red-200 text-red-700 p-4 rounded-md mb-6">
            <h3 class="font-bold">Error</h3>
            <p>${message}</p>
        </div>
    `;
}

/**
 * Shows loading indicator in the UI
 */
function showLoading(resultDiv) {
    if (!resultDiv) {
        resultDiv = document.getElementById('results');
        if (!resultDiv) {
            resultDiv = document.createElement('div');
            resultDiv.id = 'results';
            document.querySelector('main').appendChild(resultDiv);
        }
    }
    
    resultDiv.innerHTML = `
        <div class="flex items-center justify-center p-12 bg-white rounded-lg shadow">
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            <span class="ml-3 text-lg font-medium text-gray-700">Analyzing logs...</span>
        </div>
    `;
}

/**
 * Submits the form with the selected files
 */
function submitForm(e) {
    if (e) e.preventDefault();
    
    console.log('Form submission initiated');
    
    // Get form and results container
    const form = document.querySelector('form') || document.getElementById('analyzeForm');
    const resultDiv = document.getElementById('results');
    
    if (!form) {
        console.error('Form element not found');
        return;
    }
    
    // Get the files to upload
    const filesToUpload = window.droppedFiles || 
                        (document.getElementById('file-upload')?.files ? 
                        Array.from(document.getElementById('file-upload').files) : []);
    
    if (!filesToUpload || filesToUpload.length === 0) {
        showError('Please select at least one log file', resultDiv);
        return;
    }
    
    console.log(`Submitting ${filesToUpload.length} files`);
    
    // Create form data
    const formData = new FormData();
    
    // Add files
    filesToUpload.forEach(file => {
        formData.append('files', file);
        console.log(`Adding file: ${file.name} (${file.size} bytes)`);
    });
    
    // Add other form fields
    const logType = document.getElementById('logType')?.value || 'standard';
    const parser = document.getElementById('parser')?.value || '';
    const filters = document.getElementById('filters')?.value || '';
    
    formData.append('log_type', logType);
    if (parser) formData.append('parser', parser);
    if (filters) formData.append('filters', filters);
    
    // Add field filters if any
    if (Object.keys(activeFilters).length > 0) {
        // Only include non-empty filter arrays
        const filtersToApply = {};
        Object.entries(activeFilters).forEach(([key, values]) => {
            if (values && values.length > 0) {
                filtersToApply[key] = values;
            }
        });
        
        if (Object.keys(filtersToApply).length > 0) {
            formData.append('filter_fields', JSON.stringify(filtersToApply));
            console.log('Applying field filters:', filtersToApply);
        }
    }
    
    // Show loading indicator
    showLoading(resultDiv);
    
    // Submit the request
    fetch('/analyze', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        console.log('Analysis task started:', data);
        pollTaskStatus(data.task_id, resultDiv);
    })
    .catch(error => {
        console.error('Error during form submission:', error);
        showError(`Failed to start analysis: ${error.message}`, resultDiv);
    });
}

/**
 * Polls for task status and updates UI accordingly
 */
function pollTaskStatus(taskId, resultDiv) {
    console.log(`Polling for task status: ${taskId}`);
    
    fetch(`/tasks/${taskId}`)
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        return response.json();
    })
    .then(taskStatus => {
        console.log('Task status:', taskStatus.status);
        
        if (taskStatus.status === 'completed') {
            console.log('Task completed successfully');
            
            // Store results
            currentResults = taskStatus.results;
            
            // Check for detected fields
            if (taskStatus.results && taskStatus.results.detected_fields) {
                console.log('Detected fields in results, initializing filters');
                detectedFields = taskStatus.results.detected_fields;
                
                if (typeof initializeFieldFilters === 'function') {
                    initializeFieldFilters(detectedFields);
                    const filterPanel = document.getElementById('filterPanel');
                    if (filterPanel) {
                        filterPanel.classList.remove('hidden');
                    }
                } else {
                    console.warn('initializeFieldFilters function not found');
                }
            }
            
            // Display results
            if (typeof displayResults === 'function') {
                displayResults(taskStatus.results, resultDiv);
            } else {
                console.warn('displayResults function not found');
                resultDiv.innerHTML = `<pre>${JSON.stringify(taskStatus.results, null, 2)}</pre>`;
            }
        } else if (taskStatus.status === 'failed') {
            console.error('Task failed:', taskStatus.error);
            
            // Get detailed error if available
            let errorMessage = taskStatus.error || 'Analysis failed';
            if (taskStatus.results && taskStatus.results.errors && 
                taskStatus.results.errors.messages && 
                taskStatus.results.errors.messages.length > 0) {
                
                const firstError = taskStatus.results.errors.messages[0];
                
                // Check for specific pipeline errors
                if (firstError.includes("'function' object has no attribute 'process'")) {
                    errorMessage = 'Backend pipeline error: This is a known issue with firewall log processing. Try selecting a different parser or log type.';
                } else {
                    errorMessage += `: ${firstError}`;
                }
            }
            
            showError(errorMessage, resultDiv);
        } else {
            // Continue polling
            setTimeout(() => pollTaskStatus(taskId, resultDiv), 1000);
        }
    })
    .catch(error => {
        console.error('Error polling task status:', error);
        showError(`Failed to check task status: ${error.message}`, resultDiv);
    });
}

/**
 * Sets up form submission handling
 */
function setupFormSubmission() {
    const form = document.querySelector('form') || document.getElementById('analyzeForm');
    
    if (!form) {
        console.error('Form element not found');
        return;
    }
    
    console.log('Setting up form submission handler');
    
    form.addEventListener('submit', submitForm);
    
    // Set up apply filters button
    const applyFiltersBtn = document.getElementById('applyFilters');
    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', () => {
            console.log('Apply filters button clicked');
            submitForm();
        });
    }
    
    console.log('Form submission handler set up successfully');
}

/**
 * Set up log type change event to update parser options
 */
function setupLogTypeChangeEvent() {
    const logTypeSelect = document.getElementById('logType');
    
    if (!logTypeSelect) {
        console.warn('Log type select element not found');
        return;
    }
    
    logTypeSelect.addEventListener('change', function() {
        const logType = this.value;
        console.log(`Log type changed to: ${logType}`);
        updateParserOptions(logType);
    });
    
    console.log('Log type change event handler set up successfully');
}

/**
 * Main initialization function
 */
function initializeApplication() {
    console.log('Initializing application...');
    
    // Set up parser options
    updateParserOptions('standard');
    
    // Set up event handlers
    setupLogTypeChangeEvent();
    setupFormSubmission();
    
    console.log('Application initialization complete');
}

// Execute initialization when the document is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApplication);
} else {
    // DOM already loaded
    initializeApplication();
}