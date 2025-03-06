// Debug logging to confirm script is loaded
console.log('App.js loaded');

// Check for required dependencies
if (typeof React === 'undefined') console.error('React is not defined!');
if (typeof ReactDOM === 'undefined') console.error('ReactDOM is not defined!');
if (typeof lucide === 'undefined') console.error('Lucide is not defined!');

// Main LogAnalyzerApp Component
const LogAnalyzerApp = () => {
    console.log('LogAnalyzerApp function called');
    
    try {
        const [activeTab, setActiveTab] = React.useState('search');
        const [files, setFiles] = React.useState([]);
        const [loading, setLoading] = React.useState(false);
        const [results, setResults] = React.useState(null);
        const [error, setError] = React.useState(null);
        const [parser, setParser] = React.useState('');
        const [filters, setFilters] = React.useState('');
        const [logType, setLogType] = React.useState('standard'); // standard or firewall
        const [sidebarOpen, setSidebarOpen] = React.useState(true);

        // Check if lucide icons are available
        if (!lucide) {
            throw new Error("Lucide icons not loaded");
        }

        // Set up the Lucide icons we'll be using
        const icons = {
            Search: lucide.Search || (() => React.createElement('span', {}, '🔍')),
            Menu: lucide.Menu || (() => React.createElement('span', {}, '☰')),
            Database: lucide.Database || (() => React.createElement('span', {}, '🗃️')),
            Bell: lucide.Bell || (() => React.createElement('span', {}, '🔔')),
            Settings: lucide.Settings || (() => React.createElement('span', {}, '⚙️')),
            BarChart2: lucide.BarChart2 || (() => React.createElement('span', {}, '📊')),
            File: lucide.File || (() => React.createElement('span', {}, '📄')),
            Grid: lucide.Grid || (() => React.createElement('span', {}, '▦')),
            Upload: lucide.Upload || (() => React.createElement('span', {}, '⬆️')),
            Clock: lucide.Clock || (() => React.createElement('span', {}, '⏰')),
            AlertTriangle: lucide.AlertTriangle || (() => React.createElement('span', {}, '⚠️')),
            Activity: lucide.Activity || (() => React.createElement('span', {}, '📈')),
            ChevronDown: lucide.ChevronDown || (() => React.createElement('span', {}, '▼'))
        };

        const handleFileChange = (e) => {
            const selectedFiles = Array.from(e.target.files);
            const validFiles = selectedFiles.filter(file => 
                file.name.endsWith('.log') || file.name.endsWith('.txt')
            );
            
            if (validFiles.length !== selectedFiles.length) {
                setError('Some files were invalid. Only .log and .txt files are allowed.');
            }
            
            setFiles(validFiles);
            setError(null);
        };

        const handleSubmit = async (e) => {
            e.preventDefault();
            if (files.length === 0) {
                setError('Please select at least one log file');
                return;
            }
            
            setLoading(true);
            setError(null);
            setResults(null);

            try {
                const formData = new FormData();
                files.forEach(file => {
                    formData.append('files', file);
                });
                if (parser) {
                    formData.append('parser', parser);
                }
                if (filters) {
                    formData.append('filters', filters);
                }
                
                // Add log type to determine analysis mode
                formData.append('log_type', logType);

                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    throw new Error('Failed to start analysis');
                }

                const data = await response.json();
                
                const pollResults = async () => {
                    try {
                        const statusResponse = await fetch(`/tasks/${data.task_id}`);
                        const taskStatus = await statusResponse.json();
                        
                        if (taskStatus.status === 'completed' && taskStatus.results) {
                            console.log('Results received:', taskStatus.results);
                            setResults(taskStatus.results);
                            setLoading(false);
                        } else if (taskStatus.status === 'failed') {
                            throw new Error(taskStatus.error || 'Analysis failed');
                        } else if (taskStatus.status === 'processing') {
                            setTimeout(pollResults, 1000);
                        }
                    } catch (pollError) {
                        setError(pollError.message);
                        setLoading(false);
                    }
                };

                pollResults();
            } catch (err) {
                setError(err.message);
                setLoading(false);
            }
        };

        // Check if our component functions are defined
        console.log('Component checks:');
        console.log('- MetricsOverview:', typeof MetricsOverview !== 'undefined' ? 'Found' : 'NOT FOUND');
        console.log('- HttpAnalysis:', typeof HttpAnalysis !== 'undefined' ? 'Found' : 'NOT FOUND');
        console.log('- ErrorAnalysis:', typeof ErrorAnalysis !== 'undefined' ? 'Found' : 'NOT FOUND');
        console.log('- SecurityAnalysis:', typeof SecurityAnalysis !== 'undefined' ? 'Found' : 'NOT FOUND');
        console.log('- PerformanceAnalysis:', typeof PerformanceAnalysis !== 'undefined' ? 'Found' : 'NOT FOUND');
        console.log('- TimeAnalysis:', typeof TimeAnalysis !== 'undefined' ? 'Found' : 'NOT FOUND');
        console.log('- FirewallDashboard:', typeof FirewallDashboard !== 'undefined' ? 'Found' : 'NOT FOUND');

        const renderStandardParserOptions = () => {
            return [
                React.createElement('option', { value: '', key: 'auto' }, 'Auto-detect'),
                React.createElement('option', { value: 'apache_access', key: 'apache-access' }, 'Apache Access Log'),
                React.createElement('option', { value: 'apache_error', key: 'apache-error' }, 'Apache Error Log'),
                React.createElement('option', { value: 'nginx_access', key: 'nginx-access' }, 'Nginx Access Log'),
                React.createElement('option', { value: 'nginx_error', key: 'nginx-error' }, 'Nginx Error Log'),
                React.createElement('option', { value: 'syslog', key: 'syslog' }, 'Syslog')
            ];
        };

        const renderFirewallParserOptions = () => {
            return [
                React.createElement('option', { value: 'firewall', key: 'auto-firewall' }, 'Auto-detect Firewall'),
                React.createElement('option', { value: 'iptables', key: 'iptables' }, 'IPTables'),
                React.createElement('option', { value: 'pfsense', key: 'pfsense' }, 'pfSense'),
                React.createElement('option', { value: 'cisco_asa', key: 'cisco-asa' }, 'Cisco ASA'),
                React.createElement('option', { value: 'windows_firewall', key: 'windows-firewall' }, 'Windows Firewall')
            ];
        };

        const renderResults = () => {
            if (!results) return null;

            // If firewall analysis, show different components
            if (logType === 'firewall' && results.firewall_analysis) {
                return React.createElement('div', { className: 'space-y-6' }, [
                    React.createElement(FirewallDashboard, { 
                        data: results.firewall_analysis,
                        key: 'firewall-dashboard'
                    })
                ]);
            }

            console.log('Rendering standard results');
            // Standard log analysis
            return React.createElement('div', { className: 'space-y-6' }, [
                React.createElement(MetricsOverview, { 
                    data: results.summary,
                    key: 'metrics'
                }),
                React.createElement(HttpAnalysis, { 
                    data: results.http_analysis,
                    key: 'http'
                }),
                React.createElement(ErrorAnalysis, { 
                    data: results.error_analysis,
                    key: 'error'
                }),
                React.createElement(SecurityAnalysis, { 
                    data: results.security_analysis,
                    key: 'security'
                }),
                React.createElement(PerformanceAnalysis, { 
                    data: results.performance_metrics,
                    key: 'performance'
                }),
                React.createElement(TimeAnalysis, { 
                    data: results.time_analysis,
                    key: 'time'
                })
            ]);
        };

        // Simplest possible version to start with
        return React.createElement('div', { className: 'container mx-auto px-4 py-8' }, [
            React.createElement('h1', { 
                className: 'text-3xl font-bold mb-8',
                key: 'title'
            }, 'Log Analyzer'),
            
            React.createElement('div', { 
                className: 'bg-white rounded-lg shadow p-6 mb-8',
                key: 'upload'
            }, [
                React.createElement('h2', { 
                    className: 'text-xl font-semibold mb-4',
                    key: 'upload-title'
                }, 'Analyze Logs'),
                React.createElement('form', { 
                    onSubmit: handleSubmit,
                    className: 'space-y-4',
                    key: 'form'
                }, [
                    // File Input Group
                    React.createElement('div', { key: 'file-group' }, [
                        React.createElement('label', { 
                            className: 'block text-sm font-medium text-gray-700 mb-2',
                            key: 'file-label'
                        }, 'Log Files'),
                        React.createElement('input', {
                            type: 'file',
                            onChange: handleFileChange,
                            multiple: true,
                            accept: '.log,.txt',
                            className: 'block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100',
                            key: 'file-input'
                        })
                    ]),

                    // Log Type Selection
                    React.createElement('div', { key: 'log-type-group' }, [
                        React.createElement('label', {
                            className: 'block text-sm font-medium text-gray-700 mb-2',
                            key: 'log-type-label'
                        }, 'Log Type'),
                        React.createElement('select', {
                            className: 'block w-full rounded-md border border-gray-300 shadow-sm p-2',
                            value: logType,
                            onChange: (e) => {
                                setLogType(e.target.value);
                                setParser(''); // Reset parser when log type changes
                            },
                            key: 'log-type-select'
                        }, [
                            React.createElement('option', { value: 'standard', key: 'std' }, 'Standard Logs'),
                            React.createElement('option', { value: 'firewall', key: 'fw' }, 'Firewall Logs')
                        ])
                    ]),

                    // Parser Selection Group
                    React.createElement('div', { key: 'parser-group' }, [
                        React.createElement('label', {
                            className: 'block text-sm font-medium text-gray-700 mb-2',
                            key: 'parser-label'
                        }, 'Parser'),
                        React.createElement('select', {
                            className: 'block w-full rounded-md border border-gray-300 shadow-sm p-2',
                            value: parser,
                            onChange: (e) => setParser(e.target.value),
                            key: 'parser-select'
                        }, logType === 'firewall' ? renderFirewallParserOptions() : renderStandardParserOptions())
                    ]),

                    // Filters Group
                    React.createElement('div', { key: 'filter-group' }, [
                        React.createElement('label', {
                            className: 'block text-sm font-medium text-gray-700 mb-2',
                            key: 'filter-label'
                        }, 'Filters'),
                        React.createElement('input', {
                            type: 'text',
                            placeholder: "e.g. level=='ERROR'",
                            className: 'block w-full rounded-md border border-gray-300 shadow-sm p-2',
                            value: filters,
                            onChange: (e) => setFilters(e.target.value),
                            key: 'filter-input'
                        })
                    ]),

                    // Submit Button
                    React.createElement('button', {
                        type: 'submit',
                        disabled: loading || files.length === 0,
                        className: 'w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50',
                        key: 'submit'
                    }, loading ? 'Analyzing...' : 'Analyze Logs')
                ]),
                error && React.createElement('div', {
                    className: 'mt-4 p-4 rounded-md bg-red-50 text-red-700',
                    key: 'error'
                }, error)
            ]),
            
            loading && React.createElement('div', {
                className: 'flex items-center justify-center p-4',
                key: 'loading'
            }, [
                React.createElement('div', {
                    className: 'animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500',
                    key: 'spinner'
                }),
                React.createElement('span', {
                    className: 'ml-2 text-blue-700',
                    key: 'loading-text'
                }, 'Processing logs...')
            ]),
            
            renderResults()
        ]);
    } catch (err) {
        console.error('Error in LogAnalyzerApp:', err);
        return React.createElement('div', { 
            style: { 
                color: 'red', 
                padding: '20px', 
                margin: '20px',
                border: '1px solid red',
                borderRadius: '5px',
                backgroundColor: '#fff'
            } 
        }, [
            React.createElement('h2', {}, 'Error Rendering Application'),
            React.createElement('pre', {}, err.toString()),
            React.createElement('p', {}, 'Check browser console for more details.')
        ]);
    }
};

// Define FirewallDashboard if not already defined
if (typeof FirewallDashboard === 'undefined') {
    console.log('Creating fallback FirewallDashboard');
    window.FirewallDashboard = ({ data }) => {
        console.log('Rendering fallback FirewallDashboard with data:', data);
        return React.createElement('div', { className: 'bg-white p-4 rounded shadow' }, [
            React.createElement('h2', { className: 'text-xl font-bold mb-4' }, 'Firewall Analysis'),
            React.createElement('p', {}, 'Displaying simplified view - some components may be missing')
        ]);
    };
}

// Export the component globally so it can be accessed
window.LogAnalyzerApp = LogAnalyzerApp;
console.log('LogAnalyzerApp defined and exported to window');