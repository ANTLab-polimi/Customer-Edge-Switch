import pandas as pd
import plotly.express as px
import dash
from dash.dependencies import Input, Output
from dash import dcc
from dash import html

excel_file_name = './mains_csv/MainTerminal_PhaseCount.csv'

# Reading the CSV file
df = pd.read_csv(excel_file_name)

# Creating a Dash application
app = dash.Dash(__name__)

# with two graphs inside an html Div
app.layout = html.Div([
    dcc.Graph(id='live-graph'),
    dcc.Graph(id='live-graph1'),
    dcc.Interval(
        id='interval-component',
        interval=10*1000,  # Refresh of 10 seconds
        n_intervals=0
    )
])

# the callback function for the server app
@app.callback(
    Output('live-graph', 'figure'),
    Output('live-graph1', 'figure'),
    Input('interval-component', 'n_intervals')
)

# the function that will be launched everytime the server will refreshing
def update_graph(n):

    # Updating the plot with the new information inside the CSV
    updated_df = pd.read_csv(excel_file_name)

    # the first figure to be plotted
    fig = px.line(
    	updated_df,
    	x='Sensor Date Time',
    	y='kW',
    	title='Total Power of the system'
    )

    fig.update_layout(
    	#yaxis_range=[0,10]
    	yaxis=dict(rangemode = 'tozero')
    )

    # the second figure to be plotted
    Y = ['Chip Press', 'Chip Saw', 'High Temperature Oven', 'Soldering Oven', 'Washing Machine']
    
    fig2 = px.line(
    	updated_df,
    	x='Sensor Date Time',
    	y=Y,
    	labels=dict(value="kW"),
    	title='Predicted power of top 5 appliances of the system'
    )
    
    # to set the legend horizontal and not vertical on the right
    fig2.update_layout(
    	legend=dict(
    		orientation="h",
    		yanchor="bottom",
    		y=1.02,
    		xanchor="right",
    		x=1
    	)
    )
    
    return fig, fig2

if __name__ == '__main__':
    app.run_server(debug=False)
