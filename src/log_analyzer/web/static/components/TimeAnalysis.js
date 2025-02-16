const TimeAnalysis = ({ data }) => {
    const PeakTimes = () => {
        if (!data.peak_times) return null;

        return React.createElement('div', { className: 'space-y-3' },
            data.peak_times.map((peak, index) =>
                React.createElement('div', {
                    key: index,
                    className: 'bg-gray-50 p-3 rounded'
                }, [
                    React.createElement('div', {
                        className: 'flex justify-between',
                        key: 'header'
                    }, [
                        React.createElement('span', {
                            className: 'text-sm font-medium',
                            key: 'hour'
                        }, peak.hour),
                        React.createElement('span', {
                            className: 'text-sm font-medium',
                            key: 'requests'
                        }, `${peak.requests} requests`)
                    ]),
                    React.createElement('div', {
                        className: 'text-sm text-gray-600 mt-1',
                        key: 'percentage'
                    }, `${peak.percent_of_total.toFixed(1)}% of total traffic`)
                ])
            )
        );
    };

    const TrafficRates = () => {
        if (!data.timeline?.average_rate) return null;

        const rates = [
            { label: 'Per Second', value: data.timeline.average_rate.per_second },
            { label: 'Per Minute', value: data.timeline.average_rate.per_minute },
            { label: 'Per Hour', value: data.timeline.average_rate.per_hour }
        ];

        return React.createElement('div', { className: 'space-y-3' },
            rates.map((rate, index) =>
                React.createElement('div', {
                    key: index,
                    className: 'bg-gray-50 p-3 rounded'
                }, [
                    React.createElement('div', {
                        className: 'flex justify-between',
                        key: 'content'
                    }, [
                        React.createElement('span', {
                            className: 'text-sm',
                            key: 'label'
                        }, rate.label),
                        React.createElement('span', {
                            className: 'text-sm font-medium',
                            key: 'value'
                        }, rate.value.toFixed(2))
                    ])
                ])
            )
        );
    };

    return React.createElement('div', { className: 'bg-white rounded-lg shadow p-6' }, [
        React.createElement('h3', {
            className: 'text-lg font-semibold mb-4',
            key: 'title'
        }, 'Time Analysis'),
        React.createElement('div', {
            className: 'grid grid-cols-1 md:grid-cols-2 gap-6',
            key: 'content'
        }, [
            React.createElement('div', { key: 'peaks' }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'peaks-title'
                }, 'Peak Times'),
                React.createElement(PeakTimes, { key: 'peaks-content' })
            ]),
            React.createElement('div', { key: 'rates' }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'rates-title'
                }, 'Traffic Rates'),
                React.createElement(TrafficRates, { key: 'rates-content' })
            ])
        ])
    ]);
};