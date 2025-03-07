/**
 * Enhanced Firewall Dashboard Component
 * This component provides a more comprehensive view of firewall log analysis results
 */

const FirewallDashboard = ({ data }) => {
    const [activeTab, setActiveTab] = React.useState('overview');
    
    // Make sure data exists and has expected structure
    if (!data || !data.summary) {
        return React.createElement('div', { className: 'bg-white rounded-lg shadow p-6' }, [
            React.createElement('h3', { 
                className: 'text-lg font-semibold mb-4',
                key: 'title'
            }, 'Firewall Analysis'),
            React.createElement('div', {
                className: 'text-gray-500',
                key: 'no-data'
            }, 'No firewall data available')
        ]);
    }
    
    const summary = data.summary;
    
    // Overview metrics cards
    const renderOverviewCards = () => {
        return React.createElement('div', { 
            className: 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6'
        }, [
            React.createElement(MetricCard, {
                title: 'TOTAL ENTRIES',
                value: summary.total_entries.toLocaleString(),
                color: 'blue',
                key: 'total'
            }),
            React.createElement(MetricCard, {
                title: 'ALLOWED CONNECTIONS',
                value: summary.allowed_connections.toLocaleString(),
                color: 'green',
                key: 'allowed'
            }),
            React.createElement(MetricCard, {
                title: 'BLOCKED CONNECTIONS',
                value: summary.blocked_connections.toLocaleString(),
                color: 'red',
                subtitle: `${summary.blocked_percentage.toFixed(1)}% of all traffic`,
                key: 'blocked'
            }),
            React.createElement(MetricCard, {
                title: 'UNIQUE IPs',
                value: summary.unique_ips.toLocaleString(),
                color: 'yellow',
                key: 'ips'
            })
        ]);
    };
    
    // Security metrics section - displays attack patterns
    const renderSecurityMetrics = () => {
        const securityData = data.attack_summary || {};
        
        return React.createElement('div', { 
            className: 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6'
        }, [
            React.createElement(MetricCard, {
                title: 'SUSPICIOUS IPs',
                value: securityData.suspicious_ips_count || 0,
                color: 'red',
                key: 'suspicious'
            }),
            React.createElement(MetricCard, {
                title: 'PORT SCANS',
                value: securityData.port_scan_attempts || 0,
                color: 'red',
                key: 'scans'
            }),
            React.createElement(MetricCard, {
                title: 'BRUTE FORCE',
                value: securityData.brute_force_attempts || 0,
                color: 'red',
                key: 'brute'
            }),
            React.createElement(MetricCard, {
                title: 'DOS ATTEMPTS',
                value: securityData.dos_attempts || 0,
                color: 'red',
                key: 'dos'
            })
        ]);
    };
    
    // Ports table - shows blocked ports
    const renderPortsTable = () => {
        if (!data.top_blocked_ports || data.top_blocked_ports.length === 0) {
            return React.createElement('div', {
                className: 'text-gray-500 bg-gray-50 p-4 rounded-lg',
                key: 'no-ports'
            }, 'No blocked ports detected');
        }
    
        return React.createElement('div', {
            className: 'bg-white overflow-hidden shadow rounded-lg',
            key: 'ports-table'
        }, [
            React.createElement('table', {
                className: 'min-w-full divide-y divide-gray-200',
                key: 'table'
            }, [
                React.createElement('thead', {
                    className: 'bg-gray-50',
                    key: 'thead'
                }, [
                    React.createElement('tr', { key: 'header-row' }, [
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'port-header'
                        }, 'Port'),
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'service-header'
                        }, 'Service'),
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'count-header'
                        }, 'Count'),
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'percent-header'
                        }, '%')
                    ])
                ]),
                React.createElement('tbody', {
                    className: 'bg-white divide-y divide-gray-200',
                    key: 'tbody'
                }, data.top_blocked_ports.map((port, index) => 
                    React.createElement('tr', { key: `port-${index}` }, [
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900',
                            key: 'port'
                        }, port.port),
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-500',
                            key: 'service'
                        }, port.service),
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-500',
                            key: 'count'
                        }, port.count),
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-500',
                            key: 'percent'
                        }, port.percentage ? port.percentage.toFixed(1) + '%' : 'N/A')
                    ])
                ))
            ])
        ]);
    };
    
    // IPs table - shows blocked IPs
    const renderIPsTable = () => {
        if (!data.top_blocked_ips || data.top_blocked_ips.length === 0) {
            return React.createElement('div', {
                className: 'text-gray-500 bg-gray-50 p-4 rounded-lg',
                key: 'no-ips'
            }, 'No blocked IPs detected');
        }
    
        return React.createElement('div', {
            className: 'bg-white overflow-hidden shadow rounded-lg',
            key: 'ips-table'
        }, [
            React.createElement('table', {
                className: 'min-w-full divide-y divide-gray-200',
                key: 'table'
            }, [
                React.createElement('thead', {
                    className: 'bg-gray-50',
                    key: 'thead'
                }, [
                    React.createElement('tr', { key: 'header-row' }, [
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'ip-header'
                        }, 'IP Address'),
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'type-header'
                        }, 'Type'),
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'count-header'
                        }, 'Block Count')
                    ])
                ]),
                React.createElement('tbody', {
                    className: 'bg-white divide-y divide-gray-200',
                    key: 'tbody'
                }, data.top_blocked_ips.map((ip, index) => 
                    React.createElement('tr', { key: `ip-${index}` }, [
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900',
                            key: 'ip'
                        }, ip.ip),
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-500',
                            key: 'type'
                        }, ip.type || 'Unknown'),
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-500',
                            key: 'count'
                        }, ip.count)
                    ])
                ))
            ])
        ]);
    };
    
    // Traffic sources table
    const renderTrafficSourcesTable = () => {
        if (!data.top_traffic_sources || data.top_traffic_sources.length === 0) {
            return React.createElement('div', {
                className: 'text-gray-500 bg-gray-50 p-4 rounded-lg',
                key: 'no-sources'
            }, 'No traffic sources detected');
        }
    
        return React.createElement('div', {
            className: 'bg-white overflow-hidden shadow rounded-lg',
            key: 'traffic-table'
        }, [
            React.createElement('table', {
                className: 'min-w-full divide-y divide-gray-200',
                key: 'table'
            }, [
                React.createElement('thead', {
                    className: 'bg-gray-50',
                    key: 'thead'
                }, [
                    React.createElement('tr', { key: 'header-row' }, [
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'ip-header'
                        }, 'IP Address'),
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'type-header'
                        }, 'Type'),
                        React.createElement('th', {
                            scope: 'col',
                            className: 'px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider',
                            key: 'count-header'
                        }, 'Connection Count')
                    ])
                ]),
                React.createElement('tbody', {
                    className: 'bg-white divide-y divide-gray-200',
                    key: 'tbody'
                }, data.top_traffic_sources.map((source, index) => 
                    React.createElement('tr', { key: `source-${index}` }, [
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900',
                            key: 'ip'
                        }, source.ip),
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-500',
                            key: 'type'
                        }, source.type || 'Unknown'),
                        React.createElement('td', {
                            className: 'px-6 py-4 whitespace-nowrap text-sm text-gray-500',
                            key: 'count'
                        }, source.count)
                    ])
                ))
            ])
        ]);
    };
    
    // Main component render
    return React.createElement('div', { className: 'space-y-6' }, [
        // Title
        React.createElement('h2', {
            className: 'text-xl font-bold',
            key: 'title'
        }, 'Firewall Analysis Dashboard'),
        
        // Metrics cards
        renderOverviewCards(),
        
        // Security metrics if available
        data.attack_summary && renderSecurityMetrics(),
        
        // Tab Navigation
        React.createElement('div', {
            className: 'border-b border-gray-200',
            key: 'tabs'
        }, [
            React.createElement('nav', {
                className: '-mb-px flex space-x-8',
                'aria-label': 'Tabs',
                key: 'nav'
            }, ['overview', 'security', 'traffic'].map(tab => 
                React.createElement('button', {
                    key: tab,
                    onClick: () => setActiveTab(tab),
                    className: `
                        whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm
                        ${activeTab === tab ? 
                        'border-blue-500 text-blue-600' : 
                        'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}
                    `
                }, tab.charAt(0).toUpperCase() + tab.slice(1))
            ))
        ]),
        
        // Tab Content
        React.createElement('div', {
            className: 'mt-6',
            key: 'tab-content'
        }, [
            // Overview Tab
            activeTab === 'overview' && React.createElement('div', {
                className: 'grid grid-cols-1 md:grid-cols-2 gap-6',
                key: 'overview-content'
            }, [
                React.createElement('div', { key: 'ports-section' }, [
                    React.createElement('h3', {
                        className: 'text-lg font-semibold mb-4',
                        key: 'ports-title'
                    }, 'Top Blocked Ports'),
                    renderPortsTable()
                ]),
                React.createElement('div', { key: 'ips-section' }, [
                    React.createElement('h3', {
                        className: 'text-lg font-semibold mb-4',
                        key: 'ips-title'
                    }, 'Top Blocked IPs'),
                    renderIPsTable()
                ])
            ]),
            
            // Security Tab
            activeTab === 'security' && React.createElement('div', {
                className: 'grid grid-cols-1 md:grid-cols-2 gap-6',
                key: 'security-content'
            }, [
                React.createElement('div', { key: 'suspicious-section' }, [
                    React.createElement('h3', {
                        className: 'text-lg font-semibold mb-4',
                        key: 'suspicious-title'
                    }, 'Suspicious IPs'),
                    data.attack_summary && data.attack_summary.suspicious_ips && 
                    data.attack_summary.suspicious_ips.length > 0 ? 
                        React.createElement('div', {
                            className: 'bg-white overflow-hidden shadow rounded-lg',
                            key: 'suspicious-list'
                        }, [
                            React.createElement('div', {
                                className: 'px-4 py-5 sm:p-6',
                                key: 'list-container'
                            }, [
                                React.createElement('ul', {
                                    className: 'divide-y divide-gray-200',
                                    key: 'list'
                                }, data.attack_summary.suspicious_ips.map((ip, index) => 
                                    React.createElement('li', {
                                        key: index,
                                        className: 'py-3 flex justify-between'
                                    }, [
                                        React.createElement('span', {
                                            className: 'text-sm font-medium',
                                            key: 'ip'
                                        }, ip),
                                        React.createElement('span', {
                                            className: 'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800',
                                            key: 'badge'
                                        }, 'Suspicious')
                                    ])
                                ))
                            ])
                        ]) : 
                        React.createElement('div', {
                            className: 'text-gray-500 bg-gray-50 p-4 rounded-lg',
                            key: 'no-suspicious'
                        }, 'No suspicious IPs detected')
                ]),
                React.createElement('div', { key: 'reasons-section' }, [
                    React.createElement('h3', {
                        className: 'text-lg font-semibold mb-4',
                        key: 'reasons-title'
                    }, 'Block Reasons'),
                    data.top_block_reasons && data.top_block_reasons.length > 0 ?
                        React.createElement('div', {
                            className: 'bg-white p-4 rounded-lg shadow',
                            key: 'reasons-content'
                        }, [
                            React.createElement('div', {
                                className: 'space-y-2',
                                key: 'reasons-list'
                            }, data.top_block_reasons.map((reason, index) => 
                                React.createElement('div', {
                                    key: index,
                                    className: 'flex justify-between items-center bg-gray-50 p-2 rounded'
                                }, [
                                    React.createElement('span', {
                                        className: 'text-sm truncate flex-1',
                                        key: 'reason'
                                    }, reason.reason),
                                    React.createElement('span', {
                                        className: 'text-sm font-medium ml-4',
                                        key: 'count'
                                    }, reason.count)
                                ])
                            ))
                        ]) :
                        React.createElement('div', {
                            className: 'text-gray-500 bg-gray-50 p-4 rounded-lg',
                            key: 'no-reasons'
                        }, 'No block reason data available')
                ])
            ]),
            
            // Traffic Tab
            activeTab === 'traffic' && React.createElement('div', {
                className: 'grid grid-cols-1 md:grid-cols-2 gap-6',
                key: 'traffic-content'
            }, [
                React.createElement('div', { key: 'hourly-section' }, [
                    React.createElement('h3', {
                        className: 'text-lg font-semibold mb-4',
                        key: 'hourly-title'
                    }, 'Hourly Traffic'),
                    data.hourly_distribution ? 
                        React.createElement('div', {
                            className: 'bg-white p-4 rounded-lg shadow',
                            key: 'hourly-content'
                        }, [
                            React.createElement('div', {
                                className: 'space-y-3',
                                key: 'hourly-list'
                            }, Object.keys(data.hourly_distribution.traffic || {}).sort().map(hour => {
                                const totalRequests = data.hourly_distribution.traffic[hour] || 0;
                                const blockedRequests = data.hourly_distribution.blocks && 
                                                     data.hourly_distribution.blocks[hour] || 0;
                                const allowedRequests = totalRequests - blockedRequests;
                                
                                // Calculate percentages
                                const blockedPercentage = totalRequests > 0 ? 
                                                      (blockedRequests / totalRequests) * 100 : 0;
                                
                                return React.createElement('div', {
                                    key: hour,
                                    className: 'space-y-1'
                                }, [
                                    React.createElement('div', {
                                        className: 'flex justify-between text-sm',
                                        key: 'hour-header'
                                    }, [
                                        React.createElement('span', { key: 'hour' }, hour),
                                        React.createElement('span', { key: 'stats' }, 
                                            `${totalRequests.toLocaleString()} requests ${blockedRequests > 0 ? 
                                              `(${blockedRequests} blocked, ${blockedPercentage.toFixed(1)}%)` : 
                                              '(No blocks)'}`
                                        )
                                    ]),
                                    React.createElement('div', {
                                        className: 'w-full h-4 bg-gray-200 rounded-full overflow-hidden',
                                        key: 'bar'
                                    }, [
                                        React.createElement('div', { 
                                            className: 'h-4 bg-green-500 float-left',
                                            style: { width: `${100 - blockedPercentage}%` },
                                            key: 'allowed-bar'
                                        }),
                                        React.createElement('div', { 
                                            className: 'h-4 bg-red-500 float-left',
                                            style: { width: `${blockedPercentage}%` },
                                            key: 'blocked-bar'
                                        })
                                    ])
                                ]);
                            }))
                        ]) : 
                        React.createElement('div', {
                            className: 'text-gray-500 bg-gray-50 p-4 rounded-lg',
                            key: 'no-hourly'
                        }, 'No hourly traffic data available')
                ]),
                React.createElement('div', { key: 'sources-section' }, [
                    React.createElement('h3', {
                        className: 'text-lg font-semibold mb-4',
                        key: 'sources-title'
                    }, 'Top Traffic Sources'),
                    renderTrafficSourcesTable()
                ])
            ])
        ])
    ]);
};

// Helper component for metric cards
const MetricCard = ({ title, value, color, subtitle }) => {
    return React.createElement('div', { 
        className: `bg-${color}-50 border border-${color}-100 rounded-lg p-4`
    }, [
        React.createElement('div', { 
            className: `text-sm text-${color}-600 font-medium`,
            key: 'title'
        }, title),
        React.createElement('div', { 
            className: 'text-2xl font-bold mt-1',
            key: 'value'
        }, value),
        subtitle && React.createElement('div', { 
            className: 'text-sm text-gray-500 mt-1',
            key: 'subtitle'
        }, subtitle)
    ]);
};