import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Clock, Server, Shield, Activity, AlertTriangle, Users, Database } from 'lucide-react';

const MetricCard = ({ title, value, icon: Icon, color = "blue" }) => (
  <div className={`bg-${color}-50 rounded-lg p-4 border border-${color}-200`}>
    <div className="flex items-center justify-between">
      <div>
        <div className={`text-sm text-${color}-600 font-medium`}>{title}</div>
        <div className="text-2xl font-bold mt-1">{value}</div>
      </div>
      <Icon className={`text-${color}-500`} size={24} />
    </div>
  </div>
);

const Section = ({ title, children }) => (
  <div className="bg-white rounded-lg shadow p-6 mb-6">
    <h3 className="text-lg font-semibold mb-4 flex items-center">
      {title}
    </h3>
    {children}
  </div>
);

const MetricsDashboard = ({ results }) => {
  if (!results) return null;

  // Extract data for time series chart
  const timelineData = Object.entries(results.time_analysis.hourly_distribution || {})
    .map(([hour, count]) => ({
      hour,
      requests: count
    }));

  return (
    <div className="space-y-6">
      {/* Overview Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard 
          title="Total Entries" 
          value={results.summary.total_entries.toLocaleString()} 
          icon={Database}
          color="blue"
        />
        <MetricCard 
          title="Error Rate" 
          value={results.summary.error_rate} 
          icon={AlertTriangle}
          color="red"
        />
        <MetricCard 
          title="Avg Response Time" 
          value={results.summary.average_response_time} 
          icon={Activity}
          color="green"
        />
        <MetricCard 
          title="Unique IPs" 
          value={results.summary.unique_ips.toLocaleString()} 
          icon={Users}
          color="purple"
        />
      </div>

      {/* Performance Metrics */}
      <Section title="Performance Metrics">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gray-50 p-4 rounded-lg">
            <h4 className="text-sm font-medium text-gray-700 mb-2">Response Times</h4>
            <div className="space-y-2">
              {Object.entries(results.performance_metrics.response_times).map(([key, value]) => (
                <div key={key} className="flex justify-between">
                  <span className="text-gray-600">{key.toUpperCase()}</span>
                  <span className="font-medium">{value}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg">
            <h4 className="text-sm font-medium text-gray-700 mb-2">Throughput</h4>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-600">Requests/Second</span>
                <span className="font-medium">
                  {results.performance_metrics.throughput.requests_per_second}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Peak Hour</span>
                <span className="font-medium">
                  {results.performance_metrics.throughput.peak_hour.hour}
                </span>
              </div>
            </div>
          </div>
          <div className="bg-gray-50 p-4 rounded-lg">
            <h4 className="text-sm font-medium text-gray-700 mb-2">Slow Endpoints</h4>
            <div className="space-y-2">
              {results.performance_metrics.slow_endpoints.slice(0, 3).map((endpoint, i) => (
                <div key={i} className="text-sm">
                  <div className="font-medium truncate">{endpoint.endpoint}</div>
                  <div className="text-gray-600">
                    {endpoint.average_time} ({endpoint.requests} requests)
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Section>

      {/* Traffic Timeline */}
      <Section title="Traffic Timeline">
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="hour" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="requests" 
                stroke="#3B82F6" 
                name="Requests"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Section>

      {/* HTTP Analysis */}
      <Section title="HTTP Analysis">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">Status Distribution</h4>
            <div className="space-y-4">
              {Object.entries(results.http_analysis.status_distribution).map(([code, count]) => (
                <div key={code} className="space-y-1">
                  <div className="flex justify-between text-sm">
                    <span>{code}</span>
                    <span>{count.toLocaleString()}</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className={`rounded-full h-2 ${
                        code.startsWith('2') ? 'bg-green-500' :
                        code.startsWith('3') ? 'bg-blue-500' :
                        code.startsWith('4') ? 'bg-yellow-500' : 'bg-red-500'
                      }`}
                      style={{
                        width: `${(count / results.summary.total_entries * 100)}%`
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">Top Endpoints</h4>
            <div className="space-y-3">
              {results.http_analysis.top_endpoints.slice(0, 5).map((endpoint, i) => (
                <div key={i} className="flex justify-between items-center bg-gray-50 p-2 rounded">
                  <span className="text-sm truncate flex-1">{endpoint.endpoint}</span>
                  <span className="text-sm font-medium ml-4">
                    {endpoint.requests.toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Section>

      {/* Security Analysis */}
      <Section title="Security Analysis">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">Suspicious Activity</h4>
            <div className="space-y-3">
              {results.security_analysis.suspicious_ips.slice(0, 5).map((ip, i) => (
                <div key={i} className="bg-gray-50 p-3 rounded">
                  <div className="flex justify-between">
                    <span className="text-sm font-medium">{ip.ip}</span>
                    <span className="text-sm text-red-600">{ip.failed_attempts} failed attempts</span>
                  </div>
                  <div className="text-sm text-gray-600 mt-1">
                    Failure Rate: {ip.failure_rate}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">Top User Agents</h4>
            <div className="space-y-3">
              {results.security_analysis.user_agents.slice(0, 5).map((agent, i) => (
                <div key={i} className="bg-gray-50 p-2 rounded">
                  <div className="text-sm truncate">{agent.user_agent}</div>
                  <div className="text-sm text-gray-600">
                    {agent.count.toLocaleString()} requests ({agent.percentage})
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Section>
    </div>
  );
};

export default MetricsDashboard;