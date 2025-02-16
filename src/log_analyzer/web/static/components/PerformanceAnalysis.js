const PerformanceAnalysis = ({ data }) => {
    const ResponseTimes = () => {
        if (!data.response_times) return null;

        return React.createElement('div', { className: 'space-y-2' },
            Object.entries(data.response_times).map(([key, value]) =>
                React.createElement('div', {
                    key,
                    className: 'flex justify-between'
                }, [
                    React.createElement('span', {
                        className: 'text-gray-600',
                        key: 'label'
                    }, key.toUpperCase()),
                    React.createElement('span', {
                        className: 'font-medium',
                        key: 'value'
                    }, value)
                ])
            )
        );
    };

    const Throughput = () => {
        if (!data.throughput) return null;

        return React.createElement('div', { className: 'space-y-2' }, [
            React.createElement('div', {
                className: 'flex justify-between',
                key: 'rps'
            }, [
                React.createElement('span', {
                    className: 'text-gray-600',
                    key: 'label'
                }, 'Requests/Second'),
                React.createElement('span', {
                    className: 'font-medium',
                    key: 'value'
                }, data.throughput.requests_per_second)
            ]),
            React.createElement('div', {
                className: 'flex justify-between',
                key: 'peak'
            }, [
                React.createElement('span', {
                    className: 'text-gray-600',
                    key: 'label'
                }, 'Peak Hour'),
                React.createElement('span', {
                    className: 'font-medium',
                    key: 'value'
                }, data.throughput.peak_hour.hour)
            ])
        ]);
    };

    const SlowEndpoints = () => {
        if (!data.slow_endpoints) return null;

        return React.createElement('div', { className: 'space-y-2' },
            data.slow_endpoints.map((endpoint, index) =>
                React.createElement('div', {
                    key: index,
                    className: 'text-sm'
                }, [
                    React.createElement('div', {
                        className: 'font-medium truncate',
                        key: 'endpoint'
                    }, endpoint.endpoint),
                    React.createElement('div', {
                        className: 'text-gray-600',
                        key: 'stats'
                    }, `${endpoint.average_time} (${endpoint.requests} requests)`)
                ])
            )
        );
    };

    return React.createElement('div', { className: 'bg-white rounded-lg shadow p-6' }, [
        React.createElement('h3', {
            className: 'text-lg font-semibold mb-4',
            key: 'title'
        }, 'Performance Analysis'),
        React.createElement('div', {
            className: 'grid grid-cols-1 md:grid-cols-3 gap-4',
            key: 'content'
        }, [
            React.createElement('div', {
                className: 'bg-gray-50 p-4 rounded-lg',
                key: 'response'
            }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'response-title'
                }, 'Response Times'),
                React.createElement(ResponseTimes, { key: 'response-content' })
            ]),
            React.createElement('div', {
                className: 'bg-gray-50 p-4 rounded-lg',
                key: 'throughput'
            }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'throughput-title'
                }, 'Throughput'),
                React.createElement(Throughput, { key: 'throughput-content' })
            ]),
            React.createElement('div', {
                className: 'bg-gray-50 p-4 rounded-lg',
                key: 'slow'
            }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'slow-title'
                }, 'Slow Endpoints'),
                React.createElement(SlowEndpoints, { key: 'slow-content' })
            ])
        ])
    ]);
};