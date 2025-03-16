/**
 * LogAnalyzer Results Renderer
 * Renders analysis results in the UI
 */

/**
 * Displays appropriate results based on log type
 */
function displayResults(results, resultDiv) {
    console.log('Displaying results');
    
    // Create results div if it doesn't exist
    if (!resultDiv) {
        resultDiv = document.getElementById('results');
        if (!resultDiv) {
            resultDiv = document.createElement('div');
            resultDiv.id = 'results';
            document.querySelector('main').appendChild(resultDiv);
        }
    }
    
    // Clear any existing content
    resultDiv.innerHTML = '';
    
    // Check if this is a firewall analysis
    const logType = document.getElementById('logType')?.value || 'standard';
    
    if (logType === 'firewall' && results.firewall_analysis) {
        // Use React component if available
        if (typeof React !== 'undefined' && typeof ReactDOM !== 'undefined' && typeof FirewallDashboard === 'function') {
            console.log('Rendering firewall results with React');
            ReactDOM.render(
                React.createElement(FirewallDashboard, { data: results.firewall_analysis }),
                resultDiv
            );
        } else {
            console.log('Rendering firewall results with HTML fallback');
            displayFirewallResults(results.firewall_analysis, resultDiv);
        }
    } else {
        // Use React components if available
        if (typeof React !== 'undefined' && typeof ReactDOM !== 'undefined' && 
            typeof MetricsOverview === 'function' && 
            typeof HttpAnalysis === 'function' && 
            typeof ErrorAnalysis === 'function') {
            
            console.log('Rendering standard results with React');
            
            // Define components to render
            const components = [
                { Component: MetricsOverview, data: results.summary, key: 'metrics' }
            ];
            
            // Add HTTP analysis if available
            if (results.http_analysis) {
                components.push({ 
                    Component: HttpAnalysis, 
                    data: results.http_analysis, 
                    key: 'http' 
                });
            }
            
            // Add error analysis if available
            if (results.error_analysis) {
                components.push({ 
                    Component: ErrorAnalysis, 
                    data: results.error_analysis, 
                    key: 'error' 
                });
            }
            
            // Add security analysis if available
            if (results.security_analysis && typeof SecurityAnalysis === 'function') {
                components.push({ 
                    Component: SecurityAnalysis, 
                    data: results.security_analysis, 
                    key: 'security' 
                });
            }
            
            // Add performance analysis if available
            if (results.performance_metrics && typeof PerformanceAnalysis === 'function') {
                components.push({ 
                    Component: PerformanceAnalysis, 
                    data: results.performance_metrics, 
                    key: 'performance' 
                });
            }
            
            // Add time analysis if available
            if (results.time_analysis && typeof TimeAnalysis === 'function') {
                components.push({ 
                    Component: TimeAnalysis, 
                    data: results.time_analysis, 
                    key: 'time' 
                });
            }
            
            // Create elements for each component
            const elements = components.map(({ Component, data, key }) => 
                React.createElement(Component, { data, key })
            );
            
            // Render the components
            ReactDOM.render(
                React.createElement('div', { className: 'space-y-6' }, elements),
                resultDiv
            );
        } else {
            console.log('Rendering standard results with HTML fallback');
            displayStandardResults(results, resultDiv);
        }
    }
}

/**
 * Displays firewall analysis results using HTML (fallback)
 */
function displayFirewallResults(data, resultDiv) {
    if (!data || !data.summary) {
        resultDiv.innerHTML = `
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold mb-4">Firewall Analysis</h3>
                <div class="text-gray-500">No firewall data available</div>
            </div>
        `;
        return;
    }
    
    const summary = data.summary;
    
    // Create metrics cards
    const metricCards = `
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div class="bg-blue-50 border border-blue-100 rounded-lg p-4">
                <div class="text-sm text-blue-600 font-medium">TOTAL ENTRIES</div>
                <div class="text-2xl font-bold mt-1">${summary.total_entries.toLocaleString()}</div>
            </div>
            <div class="bg-green-50 border border-green-100 rounded-lg p-4">
                <div class="text-sm text-green-600 font-medium">ALLOWED CONNECTIONS</div>
                <div class="text-2xl font-bold mt-1">${summary.allowed_connections.toLocaleString()}</div>
            </div>
            <div class="bg-red-50 border border-red-100 rounded-lg p-4">
                <div class="text-sm text-red-600 font-medium">BLOCKED CONNECTIONS</div>
                <div class="text-2xl font-bold mt-1">${summary.blocked_connections.toLocaleString()}</div>
                <div class="text-sm text-gray-500 mt-1">${summary.blocked_percentage.toFixed(1)}% of all traffic</div>
            </div>
            <div class="bg-yellow-50 border border-yellow-100 rounded-lg p-4">
                <div class="text-sm text-yellow-600 font-medium">UNIQUE IPs</div>
                <div class="text-2xl font-bold mt-1">${summary.unique_ips.toLocaleString()}</div>
            </div>
        </div>
    `;
    
    // Create security metrics section if available
    const securityMetrics = data.attack_summary ? `
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div class="bg-red-50 border border-red-100 rounded-lg p-4">
                <div class="text-sm text-red-600 font-medium">SUSPICIOUS IPs</div>
                <div class="text-2xl font-bold mt-1">${data.attack_summary.suspicious_ips_count || 0}</div>
            </div>
            <div class="bg-red-50 border border-red-100 rounded-lg p-4">
                <div class="text-sm text-red-600 font-medium">PORT SCANS</div>
                <div class="text-2xl font-bold mt-1">${data.attack_summary.port_scan_attempts || 0}</div>
            </div>
            <div class="bg-red-50 border border-red-100 rounded-lg p-4">
                <div class="text-sm text-red-600 font-medium">BRUTE FORCE</div>
                <div class="text-2xl font-bold mt-1">${data.attack_summary.brute_force_attempts || 0}</div>
            </div>
            <div class="bg-red-50 border border-red-100 rounded-lg p-4">
                <div class="text-sm text-red-600 font-medium">DOS ATTEMPTS</div>
                <div class="text-2xl font-bold mt-1">${data.attack_summary.dos_attempts || 0}</div>
            </div>
        </div>
    ` : '';
    
    // Create ports table
    const portsTable = renderTable(
        data.top_blocked_ports,
        [
            { key: 'port', label: 'Port' },
            { key: 'service', label: 'Service' },
            { key: 'count', label: 'Count' },
            { 
                key: 'percentage', 
                label: '%',
                render: item => `${item.percentage ? item.percentage.toFixed(1) : '0'}%`
            }
        ],
        'No blocked ports detected'
    );
    
    // Create IPs table
    const ipsTable = renderTable(
        data.top_blocked_ips,
        [
            { key: 'ip', label: 'IP Address' },
            { key: 'type', label: 'Type' },
            { key: 'count', label: 'Block Count' }
        ],
        'No blocked IPs detected'
    );
    
    // Assemble the complete HTML
    resultDiv.innerHTML = `
        <div class="space-y-6">
            <h2 class="text-xl font-bold">Firewall Analysis Dashboard</h2>
            ${metricCards}
            ${securityMetrics}
            <div class="border-b border-gray-200">
                <nav class="-mb-px flex space-x-8" aria-label="Tabs">
                    <button class="whitespace-nowrap py-4 px-1 border-b-2 border-blue-500 text-blue-600 font-medium text-sm">Overview</button>
                    <button class="whitespace-nowrap py-4 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 font-medium text-sm">Security</button>
                    <button class="whitespace-nowrap py-4 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 font-medium text-sm">Traffic</button>
                </nav>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <h3 class="text-lg font-semibold mb-4">Top Blocked Ports</h3>
                    ${portsTable}
                </div>
                <div>
                    <h3 class="text-lg font-semibold mb-4">Top Blocked IPs</h3>
                    ${ipsTable}
                </div>
            </div>
        </div>
    `;
}

/**
 * Displays standard log analysis results using HTML (fallback)
 */
function displayStandardResults(results, resultDiv) {
    if (!results || !results.summary) {
        resultDiv.innerHTML = `
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-lg font-semibold mb-4">Log Analysis</h3>
                <div class="text-gray-500">No data available</div>
            </div>
        `;
        return;
    }
    
    const summary = results.summary;
    
    // Create metrics cards
    const metricCards = `
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="bg-blue-50 border border-blue-100 rounded-lg p-4">
                <div class="text-sm text-blue-600 font-medium">TOTAL ENTRIES</div>
                <div class="text-2xl font-bold mt-1">${summary.total_entries.toLocaleString()}</div>
            </div>
            <div class="bg-red-50 border border-red-100 rounded-lg p-4">
                <div class="text-sm text-red-600 font-medium">ERROR RATE</div>
                <div class="text-2xl font-bold mt-1">${summary.error_rate}</div>
            </div>
            <div class="bg-green-50 border border-green-100 rounded-lg p-4">
                <div class="text-sm text-green-600 font-medium">AVG RESPONSE TIME</div>
                <div class="text-2xl font-bold mt-1">${summary.average_response_time}</div>
            </div>
            <div class="bg-purple-50 border border-purple-100 rounded-lg p-4">
                <div class="text-sm text-purple-600 font-medium">UNIQUE IPs</div>
                <div class="text-2xl font-bold mt-1">${summary.unique_ips.toLocaleString()}</div>
            </div>
        </div>
    `;
    
    // Create HTTP analysis section if available
    const httpAnalysis = results.http_analysis ? `
        <div class="bg-white rounded-lg shadow p-6 mb-6">
            <h3 class="text-lg font-semibold mb-4">HTTP Analysis</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-4">Status Distribution</h4>
                    <div class="space-y-4">
                        ${Object.entries(results.http_analysis.status_distribution || {}).map(([code, count]) => `
                            <div class="space-y-1">
                                <div class="flex justify-between text-sm">
                                    <span>${code}</span>
                                    <span>${count.toLocaleString()}</span>
                                </div>
                                <div class="w-full bg-gray-200 rounded-full h-2">
                                    <div class="rounded-full h-2 ${
                                        code.startsWith('2') ? 'bg-green-500' :
                                        code.startsWith('3') ? 'bg-blue-500' :
                                        code.startsWith('4') ? 'bg-yellow-500' : 'bg-red-500'
                                    }" style="width: ${(count / summary.total_entries * 100)}%"></div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-4">Top Endpoints</h4>
                    <div class="space-y-3">
                        ${(results.http_analysis.top_endpoints || []).map(endpoint => `
                            <div class="flex justify-between items-center bg-gray-50 p-2 rounded">
                                <span class="text-sm truncate flex-1">${endpoint.endpoint}</span>
                                <span class="text-sm font-medium ml-4">${endpoint.requests.toLocaleString()}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    ` : '';
    
    // Create error analysis section if available
    const errorAnalysis = results.error_analysis ? `
        <div class="bg-white rounded-lg shadow p-6 mb-6">
            <h3 class="text-lg font-semibold mb-4">Error Analysis</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-4">Error Patterns</h4>
                    <div class="space-y-3">
                        ${(results.error_analysis.top_error_patterns || []).map(pattern => `
                            <div class="bg-gray-50 p-3 rounded">
                                <div class="text-sm font-medium truncate">${pattern.pattern}</div>
                                <div class="text-sm text-gray-600 mt-1">Count: ${pattern.count} (${pattern.percentage})</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-4">Error Timeline</h4>
                    <div class="space-y-3">
                        ${(results.error_analysis.error_timeline?.error_trends || []).slice(-5).map(trend => `
                            <div class="flex justify-between items-center bg-gray-50 p-2 rounded">
                                <span class="text-sm">${trend.hour}</span>
                                <span class="text-sm text-red-600">${trend.count} errors (${trend.rate})</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    ` : '';
    
    // Assemble the complete HTML
    resultDiv.innerHTML = `
        <div class="space-y-6">
            ${metricCards}
            ${httpAnalysis}
            ${errorAnalysis}
        </div>
    `;
}

/**
 * Helper function to render a table from data
 */
function renderTable(items, columns, emptyMessage) {
    if (!items || items.length === 0) {
        return `<div class="text-gray-500 bg-gray-50 p-4 rounded-lg">${emptyMessage}</div>`;
    }
    
    return `
        <div class="bg-white overflow-hidden shadow rounded-lg">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        ${columns.map(col => `
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                ${col.label}
                            </th>
                        `).join('')}
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    ${items.map(item => `
                        <tr>
                            ${columns.map(col => `
                                <td class="px-6 py-4 whitespace-nowrap text-sm ${col.key === 'port' || col.key === 'ip' ? 'font-medium text-gray-900' : 'text-gray-500'}">
                                    ${col.render ? col.render(item) : item[col.key] || ''}
                                </td>
                            `).join('')}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}