const SecurityAnalysis = ({ data }) => {
    const SuspiciousIPs = () => {
        if (!data.suspicious_ips) return null;

        return React.createElement('div', { className: 'space-y-3' },
            data.suspicious_ips.map((ip, index) =>
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
                            key: 'ip'
                        }, ip.ip),
                        React.createElement('span', {
                            className: 'text-sm text-red-600',
                            key: 'attempts'
                        }, `${ip.failed_attempts} attempts`)
                    ]),
                    React.createElement('div', {
                        className: 'text-sm text-gray-600 mt-1',
                        key: 'rate'
                    }, `Failure Rate: ${ip.failure_rate}`)
                ])
            )
        );
    };

    const UserAgents = () => {
        if (!data.user_agents) return null;

        return React.createElement('div', { className: 'space-y-3' },
            data.user_agents.map((agent, index) =>
                React.createElement('div', {
                    key: index,
                    className: 'bg-gray-50 p-2 rounded'
                }, [
                    React.createElement('div', {
                        className: 'text-sm truncate',
                        key: 'agent'
                    }, agent.user_agent),
                    React.createElement('div', {
                        className: 'text-sm text-gray-600',
                        key: 'stats'
                    }, `${agent.count.toLocaleString()} requests (${agent.percentage})`)
                ])
            )
        );
    };

    return React.createElement('div', { className: 'bg-white rounded-lg shadow p-6' }, [
        React.createElement('h3', {
            className: 'text-lg font-semibold mb-4',
            key: 'title'
        }, 'Security Analysis'),
        React.createElement('div', {
            className: 'grid grid-cols-1 md:grid-cols-2 gap-6',
            key: 'content'
        }, [
            React.createElement('div', { key: 'ips' }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'ips-title'
                }, 'Suspicious IPs'),
                React.createElement(SuspiciousIPs, { key: 'ips-content' })
            ]),
            React.createElement('div', { key: 'agents' }, [
                React.createElement('h4', {
                    className: 'text-sm font-medium text-gray-700 mb-2',
                    key: 'agents-title'
                }, 'Top User Agents'),
                React.createElement(UserAgents, { key: 'agents-content' })
            ])
        ])
    ]);
};