const ErrorAnalysis = ({ data }) => {
    const ErrorPatterns = () => {
        if (!data.top_error_patterns) return null;

        return React.createElement('div', { className: 'space-y-3' },
            data.top_error_patterns.map((pattern, index) =>
                React.createElement('div', {
                    key: index,
                    className: 'bg-gray-50 p-3 rounded'
                }, [
                    React.createElement('div', {
                        className: 'text-sm font-medium truncate',
                        key: 'pattern'
                    }, pattern.pattern),
                    React.createElement('div', {
                        className: 'text-sm text-gray-600 mt-1',
                        key: 'stats'
                    }, `Count: ${pattern.count} (${pattern.percentage})`)
                ])
            )
        );
    };

    const ErrorTimeline = () => {
        if (!data.error_timeline?.error_trends) return null;

        return React.createElement('div', { className: 'space-y-3' },
            data.error_timeline.error_trends.slice(-5).map((trend, index) =>
                React.createElement('div', {
                    key: index,
                    className: 'flex justify-between items-center bg-gray-50 p-2 rounded'
                }, [
                    React.createElement('span', {
                        className: 'text-sm',
                        key: 'hour'
                    }, trend.hour),
                    React.createElement('span', {
                        className: 'text-sm text-red-600',
                        key: 'count'
                    }, `${trend.count} errors (${trend.rate})`)
                ])
            )
        );
    };

    return React.createElement('div', { className: 'bg-white rounded-lg shadow p-6' }, [
        React.createElement('h3', {
            className: 'text-lg font-semibold mb-4',
            key: 'title'
        }, 'Error Analysis'),
        React.createElement('div', {
            className: 'grid grid-cols-1 md:grid-cols-2 gap-6',
            key: 'content'
        }, [
            React.createElement('div', { key: 'patterns' }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'patterns-title'
                }, 'Error Patterns'),
                React.createElement(ErrorPatterns, { key: 'patterns-content' })
            ]),
            React.createElement('div', { key: 'timeline' }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'timeline-title'
                }, 'Error Timeline'),
                React.createElement(ErrorTimeline, { key: 'timeline-content' })
            ])
        ])
    ]);
};