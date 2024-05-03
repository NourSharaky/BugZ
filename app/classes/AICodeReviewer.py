import openai

class AICodeReviewer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.client = openai.OpenAI(api_key=api_key)
        self.system_prompt = "You are an intelligent secure code reviewer. Provide detailed, accurate, and helpful security advice based on the code or issues described in technical short sentences. max 2-3 points "

    def getVulnRecommendation(self, vulnData):
      user_message = f"Review the following Python code: '{vulnData['code']}' Issue: {vulnData['issue_text']} and just give me the recommendations without text filler or context"
      completion = self.client.chat.completions.create(
          model="gpt-3.5-turbo",
          messages=[
              {"role": "system", "content": self.system_prompt},
              {"role": "user", "content": user_message}
          ]
      )
      output = completion.choices[0].message.content
      
      return output
