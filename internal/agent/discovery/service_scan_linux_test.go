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
