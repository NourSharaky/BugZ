
import streamlit as st
from streamlit_drawable_canvas import st_canvas
import pandas as pd
from src import Image, Model

model = Model()

st.set_option("deprecation.showfileUploaderEncoding", False)
st.set_page_config(page_title="Deep detect handwriting")

# Content
st.title("Deep detect handwriting")
st.markdown("""
Deep detect handwriting is a Python app based on a CNN model,
to recognize the digit that you draw on the canvas. See the [notebook
of the model's creation](https://colab.research.google.com/drive/1APQlJMs4TzP25N7oi4fhD0uGdjPS7LZZ?usp=sharing) for more details.
""")

# Sidebar
st.sidebar.header("About the author")
st.sidebar.markdown("""
**Joffrey Bienvenu**

Python dev, studying Machine Learning at BeCode.org.

 - Website: [joffreybvn.be](https://joffreybvn.be/)
 - Twitter: [@joffreybvn](https://twitter.com/Joffreybvn)
 - LinkedIn: [in/joffreybvn](https://www.linkedin.com/in/joffreybvn/)
 - Github: [joffreybvn](https://github.com/joffreybvn)
""")

st.sidebar.header("See on github")
st.sidebar.markdown("""
See the code and fork this project on Github:

[Deep Detect Handwriting repository](https://github.com/Joffreybvn/deep-detect-handwriting)
""")

col1, col2 = st.beta_columns(2)

with col1:

    # Display a h3 title
    st.subheader("Drawing area")
    st.markdown("Draw a digit. Don't make it easy !")

    # Create a canvas component
    canvas_result = st_canvas(
        stroke_width=15,
        stroke_color="#fff",
        background_color="#000",
        update_streamlit=True,
        height=290,
        width=290,
        drawing_mode="freedraw",
        key="canvas",
    )

# Instantiate an Image object from the handwritten canvas
image = Image(canvas_result.image_data)

with col2:

    # Display a h2 title
    st.subheader("What the computer see")
    st.markdown("Your drawing is resized and gray-scaled")

    # Display the transformed image
    if image.image is not None:
        st.image(image.get_streamlit_displayable(), width=290)


# Check if the user has written something
if (image.image is not None) and (not image.is_empty()):

    # Get the predicted class
    prediction = model.predict(image.get_prediction_ready())

    col3, col4 = st.beta_columns(2)

    # Display the digit predicted by the model
    with col3:
        st.subheader("Recognized digit")
        st.markdown("The digit recognized by the model")
        st.markdown(
            f'<p style="font-size: 190px;'
            f'font-weight: bold;'
            f'text-align: center;'
            f'display: flex;'
            f'flex-direction: column;'
            f'justify-content: space-around;'
            f'border: 1px solid #000;'
            f'width: 290px;'
            f'height: 290px;">{prediction}</p>',
            unsafe_allow_html=True
        )

    with col4:
        chart_data = pd.DataFrame(
            model.probabilities,
            columns=[f"{i}" for i in range(10)]
        )

        st.subheader("Probability distribution")
        st.markdown("Was your digit hard to recognize ?")
        st.bar_chart(chart_data.T)
