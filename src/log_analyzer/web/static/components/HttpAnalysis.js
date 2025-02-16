const HttpAnalysis = ({ data }) => {
    const StatusDistribution = () => {
        if (!data.status_distribution) return null;

        return React.createElement('div', { className: 'space-y-4' },
            Object.entries(data.status_distribution).map(([code, count]) => 
                React.createElement('div', { 
                    key: code,
                    className: 'space-y-1'
                }, [
                    React.createElement('div', { 
                        className: 'flex justify-between text-sm',
                        key: 'header'
                    }, [
                        React.createElement('span', {key: 'code'}, code),
                        React.createElement('span', {key: 'count'}, count.toLocaleString())
                    ]),
                    React.createElement('div', { 
                        className: 'w-full bg-gray-200 rounded-full h-2',
                        key: 'bar'
                    }, 
                        React.createElement('div', {
                            className: `rounded-full h-2 ${
                                code.startsWith('2') ? 'bg-green-500' :
                                code.startsWith('3') ? 'bg-blue-500' :
                                code.startsWith('4') ? 'bg-yellow-500' : 'bg-red-500'
                            }`,
                            style: {
                                width: `${(count / data.total_requests * 100)}%`
                            }
                        })
                    )
                ])
            )
        );
    };

    const TopEndpoints = () => {
        if (!data.top_endpoints) return null;

        return React.createElement('div', { className: 'space-y-3' },
            data.top_endpoints.map((endpoint, index) =>
                React.createElement('div', {
                    key: index,
                    className: 'flex justify-between items-center bg-gray-50 p-2 rounded'
                }, [
                    React.createElement('span', {
                        className: 'text-sm truncate flex-1',
                        key: 'endpoint'
                    }, endpoint.endpoint),
                    React.createElement('span', {
                        className: 'text-sm font-medium ml-4',
                        key: 'requests'
                    }, endpoint.requests.toLocaleString())
                ])
            )
        );
    };

    return React.createElement('div', { className: 'bg-white rounded-lg shadow p-6' }, [
        React.createElement('h3', { 
            className: 'text-lg font-semibold mb-4',
            key: 'title'
        }, 'HTTP Analysis'),
        React.createElement('div', { 
            className: 'grid grid-cols-1 md:grid-cols-2 gap-6',
            key: 'content'
        }, [
            React.createElement('div', { key: 'status' }, [
                React.createElement('h4', { 
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'status-title'
                }, 'Status Distribution'),
                React.createElement(StatusDistribution, { key: 'status-content' })
            ]),
            React.createElement('div', { key: 'endpoints' }, [
                React.createElement('h4', { 
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'endpoints-title'
                }, 'Top Endpoints'),
                React.createElement(TopEndpoints, { key: 'endpoints-content' })
            ])
        ])
    ]);
};