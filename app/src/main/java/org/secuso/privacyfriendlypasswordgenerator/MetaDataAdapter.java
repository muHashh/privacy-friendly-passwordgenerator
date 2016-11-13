package org.secuso.privacyfriendlypasswordgenerator;

import android.support.v7.widget.CardView;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import org.secuso.privacyfriendlypasswordgenerator.database.MetaData;

import java.util.ArrayList;
import java.util.List;

/**
 * Code according to the tutorial from https://code.tutsplus.com/tutorials/getting-started-with-recyclerview-and-cardview-on-android--cms-23465
 * accessed 17th June 2016
 */


public class MetaDataAdapter extends RecyclerView.Adapter<MetaDataAdapter.MetaDataViewHolder> {

    private List<MetaData> metaDataList;

    public MetaDataAdapter(List<MetaData> metaData) {

        this.metaDataList = metaData;
        //initialMetaData();
    }


    @Override
    public MetaDataViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.card_metadata, parent, false);

//        view.setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View view) {
//
//                //TODO opens generator dialog
//            }
//        });

        return new MetaDataViewHolder(view);
    }

    @Override
    public void onBindViewHolder(MetaDataViewHolder holder, int position) {
        holder.domain.setText(metaDataList.get(position).getDOMAIN());
        holder.length.setText(Integer.toString(metaDataList.get(position).getLENGTH()));
        holder.iteration.setText(Integer.toString(metaDataList.get(position).getITERATION()));
        holder.numbers = metaDataList.get(position).getHAS_NUMBERS();
        holder.symbols = metaDataList.get(position).getHAS_SYMBOLS();
        holder.letters = metaDataList.get(position).getHAS_LETTERS();
    }

    @Override
    public void onAttachedToRecyclerView(RecyclerView recyclerView) {
        super.onAttachedToRecyclerView(recyclerView);
    }

    @Override
    public int getItemCount() {
        return metaDataList.size();
    }

//    private void initialMetaData() {
//
//        metaDataList = new ArrayList<>();
//
//        MetaData a = new MetaData(1, "google.de", 13, 0, 0, 0, 1);
//        metaDataList.add(a);
//
//        MetaData b = new MetaData(1, "amazon.de", 14, 1, 1, 1, 2);
//        metaDataList.add(b);
//
//        MetaData c = new MetaData(1, "gmx.de", 15, 1, 1, 1, 5);
//        metaDataList.add(c);
//
//        MetaData d = new MetaData(1, "web.de", 16, 1, 1, 1, 11);
//        metaDataList.add(d);
//    }


    public class MetaDataViewHolder extends RecyclerView.ViewHolder {
        CardView cardView;
        TextView domain;
        TextView length;
        TextView iteration;
        ImageView numbersImageView = (ImageView) itemView.findViewById(R.id.hasNumbersImageView);
        ImageView symbolsImageView = (ImageView) itemView.findViewById(R.id.hasSymbolsImageView);
        ImageView lettersImageView = (ImageView) itemView.findViewById(R.id.hasLettersImageView);
        int numbers;
        int symbols;
        int letters;

        public MetaDataViewHolder(View itemView) {
            super(itemView);
            cardView = (CardView) itemView.findViewById(R.id.card_view);
            domain = (TextView) itemView.findViewById(R.id.domainTextView);
            length = (TextView) itemView.findViewById(R.id.length);
            iteration = (TextView) itemView.findViewById(R.id.iteration);

            //TODO: Display letters, symbols, numbers
            if (numbers == 1) {
                numbersImageView.setVisibility(View.VISIBLE);
            }
            if (symbols == 1) {
                symbolsImageView.setVisibility(View.VISIBLE);
            }
            if (letters == 1) {
                lettersImageView.setVisibility(View.VISIBLE);
            }

        }
    }

}
