package parser

import (
	"testing"
)

func TestParseResourceType_VariousCases(t *testing.T) {
	tests := []struct {
		name         string
		inputURL     string
		expectedType string
		expectedID   string
		expectError  bool
	}{
		// --- 1. 带有前缀的 Project 路径 (测试 PreprocessURLStrongBinding) ---
		{
			name:         "Project_WithExternalPrefix",
			inputURL:     "/gitlab/some/custom/path/api/v4/projects/201/repository/tags",
			expectedType: "project_tags",
			expectedID:   "201",
			expectError:  false,
		},

		// --- 2. Project 资源集合 (多后缀匹配) ---
		{
			name:         "Project_Branches_Merged",
			inputURL:     "/api/v4/projects/500/repository/merged_branches",
			expectedType: "project_branches",
			expectedID:   "500",
			expectError:  false,
		},

		// --- 3. 资源详情 (无后缀，应匹配 project_details) ---
		{
			name:         "Project_Details_ExactMatch",
			inputURL:     "/api/v4/projects/206",
			expectedType: "project_details",
			expectedID:   "206",
			expectError:  false,
		},
		{
			name:         "Project_Details_WithTrailingSlash",
			inputURL:     "/api/v4/projects/206/", // 测试尾部斜杠
			expectedType: "project_details",
			expectedID:   "206",
			expectError:  false,
		},
		// --- 3.1 id 可以是 string
		{
			name:         "Project_StringID_Match",
			inputURL:     "/api/v4/projects/my-group%2Fmy-project-slug", // URL 编码的路径/字符串 ID
			expectedType: "project_details",
			expectedID:   "my-group%2Fmy-project-slug", // 预期捕获的 ID 是整个字符串
			expectError:  false,
		},

		// --- 4. 无 ID 的资源 (project_projects) ---
		{
			name:         "Project_NoID_List",
			inputURL:     "/api/v4/projects",
			expectedType: "project_projects",
			expectedID:   "", // 预期ID为空
			expectError:  false,
		},

		// --- 5. GraphQL 资源 (非 /api/v4/) ---
		{
			name:         "Graphql_Endpoint",
			inputURL:     "/gitlab/namespaces/mlops-demo-ai-test/api/graphql",
			expectedType: "graphql_graphql",
			expectedID:   "",
			expectError:  false,
		},

		// --- 6. User 资源 (测试 /users/:id 匹配) ---
		{
			name:         "User_Details_Match",
			inputURL:     "/api/v4/users/99",
			expectedType: "user_details",
			expectedID:   "99",
			expectError:  false,
		},

		// --- 7. 错误/不匹配测试 ---
		{
			name:         "Error_UnknownPath",
			inputURL:     "/api/v4/projects/100/non_existent_resource",
			expectedType: "",
			expectedID:   "",
			expectError:  true,
		},
		{
			name:         "Error_NoAPIPrefix",
			inputURL:     "/v4/projects/100/statuses",
			expectedType: "",
			expectedID:   "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualType, actualID, err := ParseResourceType(tt.inputURL)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error but got none for URL: %s. CorePath: %s", tt.inputURL, getCorePath(t, tt.inputURL))
				}
			} else {
				if err != nil {
					t.Fatalf("Did not expect an error but got: %v. CorePath: %s", err, getCorePath(t, tt.inputURL))
				}
				if actualType != tt.expectedType {
					t.Errorf("ResourceType mismatch.\nExpected: %s\nGot:      %s", tt.expectedType, actualType)
				}
				if actualID != tt.expectedID {
					t.Errorf("ResourceID mismatch.\nExpected: %s\nGot:      %s", tt.expectedID, actualID)
				}
			}
		})
	}
}

// corePath 在测试失败时打印
func getCorePath(t *testing.T, url string) string {
	t.Helper()
	cp, err := PreprocessURLStrongBinding(url)
	if err != nil {
		return "Preprocessing Failed: " + err.Error()
	}
	return cp
}
