//go:build linux

package discovery

import "testing"

func TestInferJavaService(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		process  string
		cmdline  string
		expected string
	}{
		{
			name:     "tomcat by catalina bootstrap",
			port:     8080,
			process:  "java",
			cmdline:  "java -Dcatalina.base=/opt/tomcat -Dcatalina.home=/opt/tomcat org.apache.catalina.startup.Bootstrap start",
			expected: "tomcat",
		},
		{
			name:     "jenkins war",
			port:     8080,
			process:  "java",
			cmdline:  "java -jar /opt/jenkins/jenkins.war",
			expected: "jenkins",
		},
		{
			name:     "spring boot launcher",
			port:     8080,
			process:  "java",
			cmdline:  "java org.springframework.boot.loader.JarLauncher",
			expected: "spring-boot",
		},
		{
			name:     "generic java fallback",
			port:     9000,
			process:  "java",
			cmdline:  "java -jar app.jar",
			expected: "java-service",
		},
		{
			name:     "rocketmq namesrv",
			port:     9876,
			process:  "java",
			cmdline:  "java -jar /opt/rocketmq/rocketmq-namesrv.jar",
			expected: "rocketmq",
		},
		{
			name:     "nacos server jar",
			port:     8848,
			process:  "java",
			cmdline:  "java -jar /home/admin/nacos-server.jar",
			expected: "nacos",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferJavaService(tt.port, tt.process, tt.cmdline)
			if got != tt.expected {
				t.Fatalf("inferJavaService() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestInferServiceNamePrefersTomcatFingerprint(t *testing.T) {
	got := inferServiceName(8080, "java", "java -Dcatalina.home=/srv/tomcat org.apache.catalina.startup.Bootstrap start")
	if got != "tomcat" {
		t.Fatalf("inferServiceName() = %q, want tomcat", got)
	}
}

func TestInferServiceNameRecognizesCommonMiddleware(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		process  string
		cmdline  string
		expected string
	}{
		{
			name:     "mongodb by process",
			port:     27017,
			process:  "mongod",
			cmdline:  "/usr/bin/mongod --config /etc/mongod.conf",
			expected: "mongodb",
		},
		{
			name:     "rabbitmq by process",
			port:     5672,
			process:  "rabbitmq-server",
			cmdline:  "/usr/lib/rabbitmq/bin/rabbitmq-server",
			expected: "rabbitmq",
		},
		{
			name:     "consul by command line",
			port:     8500,
			process:  "consul",
			cmdline:  "/usr/local/bin/consul agent -server",
			expected: "consul",
		},
		{
			name:     "grafana by command line",
			port:     3000,
			process:  "grafana-server",
			cmdline:  "/usr/sbin/grafana-server --config /etc/grafana/grafana.ini",
			expected: "grafana",
		},
		{
			name:     "prometheus by port fallback",
			port:     9090,
			process:  "",
			cmdline:  "",
			expected: "prometheus",
		},
		{
			name:     "minio by process",
			port:     9000,
			process:  "minio",
			cmdline:  "minio server /data",
			expected: "minio",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferServiceName(tt.port, tt.process, tt.cmdline)
			if got != tt.expected {
				t.Fatalf("inferServiceName() = %q, want %q", got, tt.expected)
			}
		})
	}
}
