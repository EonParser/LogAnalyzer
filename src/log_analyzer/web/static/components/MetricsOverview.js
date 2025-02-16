const MetricsOverview = ({ data }) => {
    const MetricCard = ({ title, value, color }) => {
        return React.createElement('div', { 
            className: `bg-${color}-50 rounded-lg p-4 border border-${color}-100`
        }, [
            React.createElement('div', { 
                className: `text-sm text-${color}-600 font-medium`,
                key: 'title'
            }, title),
            React.createElement('div', { 
                className: 'text-2xl font-bold mt-1',
                key: 'value'
            }, value)
        ]);
    };

    return React.createElement('div', { 
        className: 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4'
    }, [
        React.createElement(MetricCard, {
            title: 'Total Entries',
            value: data.total_entries.toLocaleString(),
            color: 'blue',
            key: 'entries'
        }),
        React.createElement(MetricCard, {
            title: 'Error Rate',
            value: data.error_rate,
            color: 'red',
            key: 'error-rate'
        }),
        React.createElement(MetricCard, {
            title: 'Avg Response Time',
            value: data.average_response_time,
            color: 'green',
            key: 'response-time'
        }),
        React.createElement(MetricCard, {
            title: 'Unique IPs',
            value: data.unique_ips.toLocaleString(),
            color: 'purple',
            key: 'unique-ips'
        })
    ]);
};