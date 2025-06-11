package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
)

const htmlPage = `
<!DOCTYPE html>
<html>
<head>
    <title>Strivia Query Parameters</title>
    <style>
        body {
            display: flex;
            flex-direction: column; /* Allows content to stack */
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
            font-family: Arial, sans-serif;
            padding: 20px; /* Add some padding around the edges */
            box-sizing: border-box; /* Include padding in element's total width and height */
        }
        .container {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background-color: #ffffff;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            max-width: 800px; /* Limit width for readability */
            width: 100%; /* Ensure it takes full width up to max-width */
        }
        h1 {
            color: #333;
            margin-bottom: 20px;
        }
        pre {
            background-color: #e8e8e8;
            border: 1px solid #ccc;
            padding: 15px;
            border-radius: 5px;
            text-align: left; /* Keep code block text left-aligned */
            overflow-x: auto; /* Enable horizontal scrolling for long lines */
            white-space: pre-wrap; /* Wrap long lines */
            word-break: break-all; /* Break long words */
        }
        code {
            font-family: 'Courier New', Courier, monospace;
            color: #333;
            font-size: 1.1em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Received Query Parameters</h1>
        <pre><code>{{.JSONParams}}</code></pre>
    </div>
</body>
</html>
`

func main() {
	tmpl, _ := template.New("all_params").Parse(htmlPage)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		paramsMap := make(map[string]string)
		for key, values := range queryParams {
			if len(values) > 0 {
				paramsMap[key] = values[0]
			}
		}

		jsonData, _ := json.MarshalIndent(paramsMap, "", "    ")

		w.Header().Set("Content-Type", "text/html")
		tmpl.Execute(w, struct{ JSONParams template.HTML }{
			JSONParams: template.HTML(jsonData),
		})
	})

	log.Printf("Server starting on port :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
