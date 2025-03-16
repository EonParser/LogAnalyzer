// Define helper functions first so they're available
function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
    return false;
}

function highlight() {
    const dropZone = document.getElementById('drop-zone');
    if (dropZone) {
        dropZone.classList.add('bg-blue-50');
        dropZone.classList.add('border-blue-300');
    }
}

function unhighlight() {
    const dropZone = document.getElementById('drop-zone');
    if (dropZone) {
        dropZone.classList.remove('bg-blue-50');
        dropZone.classList.remove('border-blue-300');
    }
}

function updateFileList(files) {
    console.log('Updating file list UI with', files?.length || 0, 'files');
    const fileList = document.getElementById('fileList');
    if (!fileList) {
        console.warn('File list element not found');
        return;
    }
    
    if (!files || files.length === 0) {
        fileList.innerHTML = '';
        return;
    }
    
    const filesArray = Array.from(files);
    
    fileList.innerHTML = `<p>${filesArray.length} file(s) selected:</p>`;
    const ul = document.createElement('ul');
    ul.className = 'list-disc list-inside';
    
    filesArray.forEach(file => {
        const li = document.createElement('li');
        li.textContent = `${file.name} (${formatFileSize(file.size)})`;
        li.className = 'truncate';
        ul.appendChild(li);
    });
    
    fileList.appendChild(ul);
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' bytes';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else return (bytes / 1048576).toFixed(1) + ' MB';
}

function handleDrop(e) {
    console.log('Drop event triggered in file-uploader.js');
    unhighlight();
    
    const dt = e.dataTransfer;
    if (!dt || !dt.files) {
        console.warn('No files in drop event');
        return;
    }
    
    const files = dt.files;
    console.log(`Dropped ${files.length} files`);
    
    // Filter for only .log and .txt files
    const validFiles = Array.from(files).filter(file => 
        file.name.endsWith('.log') || file.name.endsWith('.txt')
    );
    
    if (validFiles.length === 0) {
        alert('Please upload .log or .txt files only');
        return;
    }
    
    if (validFiles.length !== files.length) {
        alert('Some files were skipped. Only .log and .txt files are supported.');
    }
    
    // Update the file list UI
    updateFileList(validFiles);
    
    // Store the valid files for form submission
    window.droppedFiles = validFiles;
    
    // Update the React app files if the function exists
    if (window.updateAppFiles && typeof window.updateAppFiles === 'function') {
        window.updateAppFiles(validFiles);
    }
    
    // Try to update the file input for browsers that support it
    try {
        const fileInput = document.getElementById('file-upload');
        if (fileInput) {
            // Create a DataTransfer object
            const dataTransfer = new DataTransfer();
            
            // Add each file to the DataTransfer object
            validFiles.forEach(file => {
                dataTransfer.items.add(file);
            });
            
            // Set the file input's files property
            fileInput.files = dataTransfer.files;
            
            // Dispatch change event
            const event = new Event('change', { bubbles: true });
            fileInput.dispatchEvent(event);
        }
    } catch (err) {
        console.error('Error updating file input:', err);
        // Continue since we have the files in window.droppedFiles
    }
}

// Set up drag and drop functionality
function setupDragAndDrop() {
    console.log('Setting up drag and drop in file-uploader.js');
    const dropZone = document.getElementById('drop-zone');
    
    if (!dropZone) {
        console.warn('Drop zone element not found');
        return;
    }
    
    console.log('Found drop zone element:', dropZone);
    
    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });
    
    // Highlight drop zone when item is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });
    
    // Handle dropped files
    dropZone.addEventListener('drop', handleDrop, false);
    
    console.log('Drag and drop event handlers attached to drop zone');
}

function initializeFileUploader() {
    console.log('Initializing file uploader...');
    
    // Set up file input change handler
    const fileInput = document.getElementById('file-upload');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            if (e.target.files && e.target.files.length > 0) {
                console.log(`Selected ${e.target.files.length} files from file input`);
                const fileArray = Array.from(e.target.files);
                
                // Store the files
                window.droppedFiles = fileArray;
                
                // Update the file list
                updateFileList(fileArray);
                
                // Update the React app files if the function exists
                if (window.updateAppFiles && typeof window.updateAppFiles === 'function') {
                    window.updateAppFiles(fileArray);
                }
            }
        });
        
        console.log('File input change handler attached');
    } else {
        console.warn('File input element not found');
    }
    
    // Set up drag and drop
    setupDragAndDrop();
}

// Export functions for use in other scripts
window.updateFileList = updateFileList;
window.setupDragAndDrop = setupDragAndDrop;
window.initializeFileUploader = initializeFileUploader;

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded - initializing file uploader');
    initializeFileUploader();
});

// Also try to initialize immediately if the DOM is already loaded
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    console.log('DOM already loaded - initializing file uploader immediately');
    initializeFileUploader();
}